package wfx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	bconfig "github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	wfxapi "github.com/siemens/wfx/generated/api"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultCMPWorkflowName is the immutable WFX workflow used to mirror the
	// Lamassu CMP transaction FSM.
	DefaultCMPWorkflowName = "lamassu.cmp.transaction.v1"

	defaultHTTPTimeout = 10 * time.Second
)

type CMPState string

const (
	CMPStateReceived          CMPState = "Received"
	CMPStateParsed            CMPState = "Parsed"
	CMPStateValidated         CMPState = "Validated"
	CMPStateResponded         CMPState = "Responded"
	CMPStateAwaitingCertConf  CMPState = "AwaitingCertConf"
	CMPStateLogicallyComplete CMPState = "LogicallyComplete"
	CMPStateConfirmed         CMPState = "Confirmed"
	CMPStateRejected          CMPState = "Rejected"
)

// CMPTransition is the WFX-side projection of one CMP transaction state
// transition.
type CMPTransition struct {
	TransactionID     string
	DMSID             string
	RequestType       string
	SubjectCommonName string
	CertSerialNumber  string
	State             CMPState
	Reason            string
	Metadata          map[string]any
}

// CMPReporter pushes CMP transaction state transitions into WFX.
type CMPReporter interface {
	Emit(ctx context.Context, transition CMPTransition) error
}

type cmpReporter struct {
	client       *wfxapi.ClientWithResponses
	logger       *logrus.Entry
	workflowName string
	tags         []string
	timeout      time.Duration

	workflowMu      sync.Mutex
	workflowEnsured bool
}

func NewCMPReporter(cfg bconfig.DMSWFXConfig, logger *logrus.Entry) (CMPReporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	cfg.BasePath = "/api/wfx/v1"

	baseURL := sdk.BuildURL(cfg.HTTPClient)
	if baseURL == "" {
		return nil, errors.New("wfx cmp reporter requires a non-empty base URL")
	}

	httpClient, err := sdk.BuildHTTPClient(cfg.HTTPClient, logger)
	if err != nil {
		return nil, fmt.Errorf("build wfx HTTP client: %w", err)
	}

	timeout := time.Duration(cfg.Timeout)
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}

	httpClient.Timeout = timeout

	client, err := wfxapi.NewClientWithResponses(baseURL, wfxapi.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("create wfx API client: %w", err)
	}

	workflowName := cfg.Workflow
	if workflowName == "" {
		workflowName = DefaultCMPWorkflowName
	}

	return &cmpReporter{
		client:       client,
		logger:       logger.WithField("component", "cmp-wfx"),
		workflowName: workflowName,
		tags:         append([]string(nil), cfg.Tags...),
		timeout:      timeout,
	}, nil
}

func (r *cmpReporter) Emit(ctx context.Context, transition CMPTransition) error {
	if transition.TransactionID == "" {
		return errors.New("missing CMP transaction ID")
	}

	ctx, cancel := withoutCancelWithTimeout(ctx, r.timeout)
	defer cancel()

	if err := r.ensureWorkflow(ctx); err != nil {
		return err
	}

	job, created, err := r.ensureJob(ctx, transition)
	if err != nil {
		return err
	}
	if job == nil {
		return errors.New("wfx returned a nil job")
	}

	// The workflow starts in Received, so job creation alone already captures
	// the first state without needing an explicit same-state update.
	if created && transition.State == CMPStateReceived {
		return nil
	}

	if job.Status != nil && job.Status.State == string(transition.State) && transition.Reason == "" && len(transition.Metadata) == 0 && transition.CertSerialNumber == "" && transition.SubjectCommonName == "" && transition.RequestType == "" {
		return nil
	}

	status := wfxapi.PutJobsIdStatusJSONRequestBody{
		State: string(transition.State),
	}
	if transition.Reason != "" {
		status.Message = transition.Reason
	}

	statusContext := buildStatusContext(transition)
	if len(statusContext) > 0 {
		status.Context = &statusContext
	}

	resp, err := r.client.PutJobsIdStatusWithResponse(ctx, job.ID, nil, status)
	if err != nil {
		return fmt.Errorf("update WFX job %s status to %s: %w", job.ID, transition.State, err)
	}
	if resp.JSON200 != nil {
		return nil
	}
	return fmt.Errorf("update WFX job %s status to %s failed: HTTP %d", job.ID, transition.State, resp.StatusCode())
}

func (r *cmpReporter) ensureWorkflow(ctx context.Context) error {
	r.workflowMu.Lock()
	defer r.workflowMu.Unlock()

	if r.workflowEnsured {
		return nil
	}

	getResp, err := r.client.GetWorkflowsNameWithResponse(ctx, r.workflowName, nil)
	if err != nil {
		return fmt.Errorf("lookup WFX workflow %q: %w", r.workflowName, err)
	}
	if getResp.JSON200 != nil {
		r.workflowEnsured = true
		return nil
	}
	if getResp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("lookup WFX workflow %q returned HTTP %d", r.workflowName, getResp.StatusCode())
	}

	createResp, err := r.client.PostWorkflowsWithResponse(ctx, nil, wfxapi.PostWorkflowsJSONRequestBody(defaultCMPWorkflow(r.workflowName)))
	if err != nil {
		return fmt.Errorf("create WFX workflow %q: %w", r.workflowName, err)
	}
	switch {
	case createResp.JSON201 != nil:
		r.workflowEnsured = true
		return nil
	case createResp.JSON400 != nil && workflowAlreadyExists(createResp.JSON400):
		r.workflowEnsured = true
		return nil
	default:
		return fmt.Errorf("create WFX workflow %q failed: HTTP %d", r.workflowName, createResp.StatusCode())
	}
}

func (r *cmpReporter) ensureJob(ctx context.Context, transition CMPTransition) (*wfxapi.Job, bool, error) {
	limit := int32(1)
	params := &wfxapi.GetJobsParams{
		ParamClientID: ptr(transition.TransactionID),
		ParamWorkflow: ptr(r.workflowName),
		ParamLimit:    &limit,
	}

	getResp, err := r.client.GetJobsWithResponse(ctx, params)
	if err != nil {
		return nil, false, fmt.Errorf("query WFX jobs for tx %s: %w", transition.TransactionID, err)
	}
	if getResp.JSON200 != nil && len(getResp.JSON200.Content) > 0 {
		job := getResp.JSON200.Content[0]
		return &job, false, nil
	}
	if getResp.JSON200 == nil {
		return nil, false, fmt.Errorf("query WFX jobs for tx %s failed: HTTP %d", transition.TransactionID, getResp.StatusCode())
	}

	body := wfxapi.PostJobsJSONRequestBody{
		ClientID:   transition.TransactionID,
		Workflow:   r.workflowName,
		Definition: buildJobDefinition(transition),
	}
	if len(r.tags) > 0 {
		tags := wfxapi.TagList(append([]string(nil), r.tags...))
		body.Tags = &tags
	}

	createResp, err := r.client.PostJobsWithResponse(ctx, nil, body)
	if err != nil {
		return nil, false, fmt.Errorf("create WFX job for tx %s: %w", transition.TransactionID, err)
	}
	if createResp.JSON201 != nil {
		return createResp.JSON201, true, nil
	}
	return nil, false, fmt.Errorf("create WFX job for tx %s failed: HTTP %d", transition.TransactionID, createResp.StatusCode())
}

func defaultCMPWorkflow(name string) wfxapi.Workflow {
	activeStates := []string{
		string(CMPStateReceived),
		string(CMPStateParsed),
		string(CMPStateValidated),
		string(CMPStateResponded),
		string(CMPStateAwaitingCertConf),
	}
	terminalStates := []string{
		string(CMPStateLogicallyComplete),
		string(CMPStateConfirmed),
		string(CMPStateRejected),
	}
	return wfxapi.Workflow{
		Name:        name,
		Description: "Lamassu CMP enrollment transaction lifecycle",
		Groups: []wfxapi.Group{
			{
				Name:        "ACTIVE",
				Description: "CMP transactions still in-flight on the server side",
				States:      activeStates,
			},
			{
				Name:        "TERMINAL",
				Description: "CMP transactions that reached a terminal outcome",
				States:      terminalStates,
			},
		},
		States: []wfxapi.State{
			{Name: string(CMPStateReceived), Description: "CMP request accepted by Lamassu"},
			{Name: string(CMPStateParsed), Description: "PKIMessage and PKIHeader decoded"},
			{Name: string(CMPStateValidated), Description: "Request protection and enrollment request validated"},
			{Name: string(CMPStateResponded), Description: "Certificate issued and IP or CP response emitted by Lamassu"},
			{Name: string(CMPStateAwaitingCertConf), Description: "Explicit certConf still pending"},
			{Name: string(CMPStateLogicallyComplete), Description: "Implicit confirmation granted"},
			{Name: string(CMPStateConfirmed), Description: "certConf validated and pkiConf returned"},
			{Name: string(CMPStateRejected), Description: "Transaction rejected or failed"},
		},
		Transitions: []wfxapi.Transition{
			{From: string(CMPStateReceived), To: string(CMPStateParsed), Eligible: wfxapi.WFX},
			{From: string(CMPStateParsed), To: string(CMPStateValidated), Eligible: wfxapi.WFX},
			{From: string(CMPStateParsed), To: string(CMPStateRejected), Eligible: wfxapi.WFX},
			{From: string(CMPStateValidated), To: string(CMPStateResponded), Eligible: wfxapi.WFX},
			{From: string(CMPStateValidated), To: string(CMPStateRejected), Eligible: wfxapi.WFX},
			{From: string(CMPStateResponded), To: string(CMPStateAwaitingCertConf), Eligible: wfxapi.WFX},
			{From: string(CMPStateResponded), To: string(CMPStateLogicallyComplete), Eligible: wfxapi.WFX},
			{From: string(CMPStateAwaitingCertConf), To: string(CMPStateConfirmed), Eligible: wfxapi.WFX},
			{From: string(CMPStateAwaitingCertConf), To: string(CMPStateRejected), Eligible: wfxapi.WFX},
		},
	}
}

func buildJobDefinition(transition CMPTransition) map[string]any {
	definition := map[string]any{
		"transactionId": transition.TransactionID,
		"dmsId":         transition.DMSID,
	}
	if transition.RequestType != "" {
		definition["requestType"] = transition.RequestType
	}
	if transition.SubjectCommonName != "" {
		definition["subjectCommonName"] = transition.SubjectCommonName
	}
	if transition.CertSerialNumber != "" {
		definition["certSerialNumber"] = transition.CertSerialNumber
	}
	return definition
}

func buildStatusContext(transition CMPTransition) map[string]any {
	contextMap := map[string]any{
		"transactionId": transition.TransactionID,
	}
	if transition.DMSID != "" {
		contextMap["dmsId"] = transition.DMSID
	}
	if transition.RequestType != "" {
		contextMap["requestType"] = transition.RequestType
	}
	if transition.SubjectCommonName != "" {
		contextMap["subjectCommonName"] = transition.SubjectCommonName
	}
	if transition.CertSerialNumber != "" {
		contextMap["certSerialNumber"] = transition.CertSerialNumber
	}
	if transition.Reason != "" {
		contextMap["reason"] = transition.Reason
	}
	for k, v := range transition.Metadata {
		contextMap[k] = v
	}
	return contextMap
}

func workflowAlreadyExists(resp *wfxapi.ErrorResponse) bool {
	if resp == nil || resp.Errors == nil {
		return false
	}
	for _, err := range *resp.Errors {
		if strings.Contains(strings.ToLower(err.Message), "already exists") {
			return true
		}
	}
	return false
}

func withoutCancelWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	} else {
		ctx = context.WithoutCancel(ctx)
	}
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func ptr[T any](v T) *T {
	return &v
}

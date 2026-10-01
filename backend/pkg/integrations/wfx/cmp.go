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
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	wfxapi "github.com/siemens/wfx/generated/api"
	"github.com/sirupsen/logrus"
)

const (
	// CMPWorkflowNameDirect is the WFX workflow mirroring the synchronous CMP
	// transaction FSM: the certificate is issued and returned inline.
	CMPWorkflowNameDirect = "lamassu.cmp.transaction.direct.v1"

	// CMPWorkflowNamePhased is the WFX workflow mirroring the admin-gated CMP
	// transaction FSM: after validation the request waits in AwaitingApproval
	// until an administrator approves issuance.
	CMPWorkflowNamePhased = "lamassu.cmp.transaction.phased.v1"

	// DefaultCMPWorkflowName is the workflow used when a DMS (or the WFX config)
	// does not specify one. Defaults to the direct (synchronous) workflow.
	DefaultCMPWorkflowName = CMPWorkflowNameDirect

	defaultHTTPTimeout = 10 * time.Second
)

// CMPState is the WFX-side name of a CMP transaction state. It is the same
// type as the persisted transaction state: one vocabulary for both.
type CMPState = models.CMPTransactionState

const (
	CMPStateReceived            = models.CMPTransactionStateReceived
	CMPStateValidated           = models.CMPTransactionStateValidated
	CMPStateAwaitingPoPResponse = models.CMPTransactionStateAwaitingPoPResponse
	CMPStateAwaitingApproval    = models.CMPTransactionStateAwaitingApproval
	CMPStateApproving           = models.CMPTransactionStateApproving
	CMPStateResponded           = models.CMPTransactionStateResponded
	CMPStateAwaitingCertConf    = models.CMPTransactionStateAwaitingCertConf
	CMPStateLogicallyComplete   = models.CMPTransactionStateLogicallyComplete
	CMPStateConfirmed           = models.CMPTransactionStateConfirmed
	CMPStateRevoking            = models.CMPTransactionStateRevoking
	CMPStateRevoked             = models.CMPTransactionStateRevoked
	CMPStateRejected            = models.CMPTransactionStateRejected
	CMPStateIssueFailed         = models.CMPTransactionStateIssueFailed
	CMPStateExpired             = models.CMPTransactionStateExpired
)

// CMP transaction actors. WFX's own Eligible enum only distinguishes CLIENT
// from WFX, and in Lamassu every transition is performed by the backend (the
// device's ir and the PKI's ip are both notified through the server), so the
// WFX eligibility is always WFX. The semantically meaningful actor — who the
// transition logically belongs to — is carried in the transition Description
// field instead, where the management UI reads it to label each edge.
const (
	CMPActorDevice = "device"
	CMPActorPKI    = "PKI"
	CMPActorAdmin  = "admin"
)

// WorkflowNameFor maps a DMS's CMP workflow selection to the WFX workflow name.
// An empty/unknown selection falls back to the direct workflow.
func WorkflowNameFor(selection models.CMPWorkflow) string {
	if selection == models.CMPWorkflowPhased {
		return CMPWorkflowNamePhased
	}
	return CMPWorkflowNameDirect
}

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
	// Principals identifies the authenticated authorization subjects that
	// initiated an admin-driven transition such as approval or rejection.
	Principals []string
	Metadata   map[string]any
	// Workflow is the WFX workflow name this transition belongs to. When empty
	// the reporter falls back to its configured default workflow. Set it from
	// the DMS's workflow selection so a device's job is created in (and only
	// transitions within) the matching direct/phased workflow.
	Workflow string
}

// CMPReporter pushes CMP transaction state transitions into WFX.
//
// Emit returns the WFX job ID associated with the transition's
// SubjectCommonName so callers can persist it alongside the CMP transaction
// row (used to deep-link the management UI to the corresponding WFX job).
// When SubjectCommonName is empty the call is dropped silently and the
// returned jobID is "" — this lets the controller emit the early Received
// lifecycle state before the CSR has been parsed without WFX rejecting it
// for lack of a meaningful client identifier.
type CMPReporter interface {
	Emit(ctx context.Context, transition CMPTransition) (jobID string, err error)
}

type cmpReporter struct {
	client       *wfxapi.ClientWithResponses
	logger       *logrus.Entry
	workflowName string
	tags         []string
	timeout      time.Duration

	workflowMu       sync.Mutex
	ensuredWorkflows map[string]struct{}
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
		client:           client,
		logger:           logger.WithField("component", "cmp-wfx"),
		workflowName:     workflowName,
		tags:             append([]string(nil), cfg.Tags...),
		timeout:          timeout,
		ensuredWorkflows: map[string]struct{}{},
	}, nil
}

// resolveWorkflowName returns the workflow a transition belongs to: the
// transition's own Workflow when set, otherwise the reporter's configured
// default.
func (r *cmpReporter) resolveWorkflowName(transition CMPTransition) string {
	if transition.Workflow != "" {
		return transition.Workflow
	}
	return r.workflowName
}

func (r *cmpReporter) Emit(ctx context.Context, transition CMPTransition) (string, error) {
	if transition.TransactionID == "" {
		return "", errors.New("missing CMP transaction ID")
	}

	// The WFX job is keyed by SubjectCommonName (= device ID). For early
	// lifecycle states emitted before the CSR is parsed (Received, Parsed
	// for pollReq/certConf flows where the CN is not directly available)
	// we cannot create or look up a job, so we drop the call silently.
	// The transactionID is still kept inside the job's definition once a
	// later, CN-bearing transition creates it.
	if transition.SubjectCommonName == "" {
		return "", nil
	}

	ctx, cancel := withoutCancelWithTimeout(ctx, r.timeout)
	defer cancel()

	workflowName := r.resolveWorkflowName(transition)
	if transition.Workflow == "" {
		// Callers outside a CMP request (e.g. the confirmation monitor) do not
		// know which workflow the DMS selected. Falling back to the default
		// would miss a job living in the other workflow and open an orphan one
		// there, leaving the real job stuck in its last state.
		workflowName = r.locateJobWorkflow(ctx, transition, workflowName)
	}
	if err := r.ensureWorkflow(ctx, workflowName); err != nil {
		return "", err
	}

	job, _, err := r.ensureJob(ctx, transition, workflowName)
	if err != nil {
		return "", err
	}
	if job == nil {
		return "", errors.New("wfx returned a nil job")
	}

	// Same-state suppression: if the job is already in this exact state and the
	// transition carries no diagnostic payload (no reason, metadata, cert
	// serial, request type), there is nothing to push.
	//
	// IMPORTANT: this MUST be checked even on a freshly-created job, because
	// the workflow starts in CMPStateReceived. The previous "if created &&
	// transition.State == CMPStateReceived" early return dropped the very
	// first PUT /status call — which is exactly the one that attaches the
	// inbound IR/CR/KUR DER (cmpRequestB64) to the Received state's context.
	// The result was that the dashboard's per-snapshot ASN.1 viewer never had
	// any payload to show on the Received state.
	if job.Status != nil && job.Status.State == string(transition.State) && transition.Reason == "" && len(transition.Principals) == 0 && len(transition.Metadata) == 0 && transition.CertSerialNumber == "" && transition.RequestType == "" {
		return job.ID, nil
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
		return "", fmt.Errorf("update WFX job %s status to %s: %w", job.ID, transition.State, err)
	}
	if resp.JSON200 != nil {
		return job.ID, nil
	}
	return "", fmt.Errorf("update WFX job %s status to %s failed: HTTP %d", job.ID, transition.State, resp.StatusCode())
}

func (r *cmpReporter) ensureWorkflow(ctx context.Context, name string) error {
	r.workflowMu.Lock()
	defer r.workflowMu.Unlock()

	if _, ok := r.ensuredWorkflows[name]; ok {
		return nil
	}

	getResp, err := r.client.GetWorkflowsNameWithResponse(ctx, name, nil)
	if err != nil {
		return fmt.Errorf("lookup WFX workflow %q: %w", name, err)
	}
	if getResp.JSON200 != nil {
		r.ensuredWorkflows[name] = struct{}{}
		return nil
	}
	if getResp.StatusCode() != http.StatusNotFound {
		return fmt.Errorf("lookup WFX workflow %q returned HTTP %d", name, getResp.StatusCode())
	}

	createResp, err := r.client.PostWorkflowsWithResponse(ctx, nil, wfxapi.PostWorkflowsJSONRequestBody(cmpWorkflowForName(name)))
	if err != nil {
		return fmt.Errorf("create WFX workflow %q: %w", name, err)
	}
	switch {
	case createResp.JSON201 != nil:
		r.ensuredWorkflows[name] = struct{}{}
		return nil
	case createResp.JSON400 != nil && workflowAlreadyExists(createResp.JSON400):
		r.ensuredWorkflows[name] = struct{}{}
		return nil
	default:
		return fmt.Errorf("create WFX workflow %q failed: HTTP %d: %s", name, createResp.StatusCode(), strings.TrimSpace(string(createResp.Body)))
	}
}

// ensureJob locates the WFX job for the given transition or creates one if it
// does not yet exist. Jobs are keyed by clientId = SubjectCommonName (device
// ID), so a single device's enrollments collapse onto one workflow row in WFX.
// To distinguish between multiple concurrent transactions for the same device
// we narrow the lookup by definition_hash and additionally verify the
// definition.transactionId once the job is found — this avoids racing two
// IRs from the same device into the same WFX job.
func (r *cmpReporter) ensureJob(ctx context.Context, transition CMPTransition, workflowName string) (*wfxapi.Job, bool, error) {
	existing, err := r.findJob(ctx, transition, workflowName)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		return existing, false, nil
	}

	body := wfxapi.PostJobsJSONRequestBody{
		ClientID:   transition.SubjectCommonName,
		Workflow:   workflowName,
		Definition: buildJobDefinition(transition),
	}
	if len(r.tags) > 0 {
		tags := wfxapi.TagList(append([]string(nil), r.tags...))
		body.Tags = &tags
	}

	createResp, err := r.client.PostJobsWithResponse(ctx, nil, body)
	if err != nil {
		return nil, false, fmt.Errorf("create WFX job for tx %s (device %s): %w", transition.TransactionID, transition.SubjectCommonName, err)
	}
	if createResp.JSON201 != nil {
		return createResp.JSON201, true, nil
	}
	return nil, false, fmt.Errorf("create WFX job for tx %s (device %s) failed: HTTP %d", transition.TransactionID, transition.SubjectCommonName, createResp.StatusCode())
}

// findJob looks up the job of the transition's transaction inside one
// workflow. It returns (nil, nil) when the workflow has no such job.
func (r *cmpReporter) findJob(ctx context.Context, transition CMPTransition, workflowName string) (*wfxapi.Job, error) {
	limit := int32(100)
	params := &wfxapi.GetJobsParams{
		ParamClientID: ptr(transition.SubjectCommonName),
		ParamWorkflow: ptr(workflowName),
		ParamLimit:    &limit,
	}

	getResp, err := r.client.GetJobsWithResponse(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("query WFX jobs for device %s: %w", transition.SubjectCommonName, err)
	}
	if getResp.JSON200 == nil {
		return nil, fmt.Errorf("query WFX jobs for device %s failed: HTTP %d", transition.SubjectCommonName, getResp.StatusCode())
	}
	for i := range getResp.JSON200.Content {
		job := getResp.JSON200.Content[i]
		if jobMatchesTransaction(&job, transition.TransactionID) {
			return &job, nil
		}
	}
	return nil, nil
}

// locateJobWorkflow returns the workflow that already holds the job of the
// transition's transaction, checking preferred first and then every CMP
// workflow. It returns preferred when no workflow has the job (or the lookups
// fail), so the caller keeps its previous behaviour.
func (r *cmpReporter) locateJobWorkflow(ctx context.Context, transition CMPTransition, preferred string) string {
	candidates := []string{preferred}
	for _, name := range []string{CMPWorkflowNameDirect, CMPWorkflowNamePhased} {
		if name != preferred {
			candidates = append(candidates, name)
		}
	}
	for _, name := range candidates {
		job, err := r.findJob(ctx, transition, name)
		if err != nil {
			r.logger.WithField("workflow", name).Debugf("could not look up WFX job for tx %s: %v", transition.TransactionID, err)
			continue
		}
		if job != nil {
			return name
		}
	}
	return preferred
}

// jobMatchesTransaction reports whether a WFX job's definition.transactionId
// matches the given txID. This is the secondary key that lets us tell apart
// concurrent enrollments for the same device.
func jobMatchesTransaction(job *wfxapi.Job, txID string) bool {
	if job == nil || job.Definition == nil {
		return false
	}
	got, ok := job.Definition["transactionId"].(string)
	return ok && got == txID
}

// cmpWorkflowForName returns the WFX workflow definition matching the given
// name. Unknown names default to the direct (synchronous) workflow.
func cmpWorkflowForName(name string) wfxapi.Workflow {
	if name == CMPWorkflowNamePhased {
		return phasedCMPWorkflow(name)
	}
	return directCMPWorkflow(name)
}

// cmpEdge builds a transition. Every CMP transition is performed by the backend
// (WFX-eligible); the logical actor(s) (device/PKI/admin) are carried in the
// Description so the management UI can label the edge. A transition that more
// than one actor can trigger lists them all, comma-separated.
func cmpEdge(from, to CMPState, actors ...string) wfxapi.Transition {
	return wfxapi.Transition{
		From:        string(from),
		To:          string(to),
		Eligible:    wfxapi.WFX,
		Description: strings.Join(actors, ", "),
	}
}

// commonCMPStates are the states shared by the direct and phased workflows.
// Received comes first: it is the workflow's initial state.
func commonCMPStates() []wfxapi.State {
	return []wfxapi.State{
		{Name: string(CMPStateReceived), Description: "CMP request accepted and PKIMessage decoded by Lamassu"},
		{Name: string(CMPStateValidated), Description: "Request protection and enrollment request validated"},
		{Name: string(CMPStateAwaitingPoPResponse), Description: "Proof-of-possession challenge sent; waiting for the end entity's popdecr"},
		{Name: string(CMPStateResponded), Description: "Certificate issued and IP or CP response emitted by Lamassu"},
		{Name: string(CMPStateAwaitingCertConf), Description: "Certificate issued; explicit certConf still pending"},
		{Name: string(CMPStateLogicallyComplete), Description: "Implicit confirmation granted"},
		{Name: string(CMPStateConfirmed), Description: "certConf validated and pkiConf returned"},
		{Name: string(CMPStateRevoking), Description: "Certificate revocation in progress (retried until the CA confirms it)"},
		{Name: string(CMPStateRevoked), Description: "Certificate revoked"},
		{Name: string(CMPStateRejected), Description: "Request rejected by validation, policy or an administrator"},
		{Name: string(CMPStateIssueFailed), Description: "The CA failed to issue the certificate"},
		{Name: string(CMPStateExpired), Description: "Approval or proof-of-possession window elapsed with no action"},
	}
}

// completedCMPStates are the states where the enrollment succeeded. They are
// not terminal: the certificate can still be revoked afterwards.
func completedCMPStates() []string {
	return []string{string(CMPStateLogicallyComplete), string(CMPStateConfirmed)}
}

// terminalCMPStates are the end states shared by every CMP workflow.
func terminalCMPStates() []string {
	return []string{string(CMPStateRevoked), string(CMPStateRejected), string(CMPStateIssueFailed), string(CMPStateExpired)}
}

// assembleCMPWorkflow builds a workflow from the parts that vary between
// variants — the active-state list, any states beyond the common set, and the
// transition list — sharing the common states and group scaffolding. The
// transition list is kept explicit per variant so the state machine stays
// auditable against the RFC.
func assembleCMPWorkflow(name, description string, activeStates []string, extraStates []wfxapi.State, transitions []wfxapi.Transition) wfxapi.Workflow {
	return wfxapi.Workflow{
		Name:        name,
		Description: description,
		Groups:      cmpGroups(activeStates, completedCMPStates(), terminalCMPStates()),
		States:      append(commonCMPStates(), extraStates...),
		Transitions: transitions,
	}
}

func cmpGroups(active, completed, terminal []string) []wfxapi.Group {
	return []wfxapi.Group{
		{Name: "ACTIVE", Description: "CMP transactions still in-flight on the server side", States: active},
		{Name: "COMPLETED", Description: "CMP transactions whose enrollment succeeded; the certificate may still be revoked", States: completed},
		{Name: "TERMINAL", Description: "CMP transactions that reached a terminal outcome", States: terminal},
	}
}

// postIssuanceCMPTransitions are the transitions shared by every workflow from
// the moment the certificate is issued: confirmation (explicit or implicit),
// the confirmation-timeout revocation, and revocation of a confirmed
// certificate.
func postIssuanceCMPTransitions() []wfxapi.Transition {
	return []wfxapi.Transition{
		cmpEdge(CMPStateResponded, CMPStateAwaitingCertConf, CMPActorPKI),
		cmpEdge(CMPStateResponded, CMPStateLogicallyComplete, CMPActorPKI),
		cmpEdge(CMPStateAwaitingCertConf, CMPStateConfirmed, CMPActorDevice),
		cmpEdge(CMPStateAwaitingCertConf, CMPStateRejected, CMPActorPKI),
		// The monitor claims an unconfirmed certificate (Revoking) and revokes it
		// at the CA (Revoked). A failed CA call leaves the transaction in Revoking
		// and is retried on the next tick: WFX rejects cyclic workflows, so there
		// is deliberately no edge back to AwaitingCertConf.
		cmpEdge(CMPStateAwaitingCertConf, CMPStateRevoking, CMPActorPKI),
		cmpEdge(CMPStateRevoking, CMPStateRevoked, CMPActorPKI),
		// Revocation requested through CMP rr or the API.
		cmpEdge(CMPStateAwaitingCertConf, CMPStateRevoked, CMPActorDevice, CMPActorAdmin),
		cmpEdge(CMPStateConfirmed, CMPStateRevoked, CMPActorDevice, CMPActorAdmin),
		cmpEdge(CMPStateLogicallyComplete, CMPStateRevoked, CMPActorDevice, CMPActorAdmin),
	}
}

// popCMPTransitions are the challengeResp proof-of-possession transitions: the
// server parks the request until the end entity answers the challenge.
func popCMPTransitions() []wfxapi.Transition {
	return []wfxapi.Transition{
		cmpEdge(CMPStateValidated, CMPStateAwaitingPoPResponse, CMPActorPKI),
		cmpEdge(CMPStateAwaitingPoPResponse, CMPStateResponded, CMPActorDevice),
		cmpEdge(CMPStateAwaitingPoPResponse, CMPStateRejected, CMPActorPKI),
		cmpEdge(CMPStateAwaitingPoPResponse, CMPStateIssueFailed, CMPActorPKI),
		cmpEdge(CMPStateAwaitingPoPResponse, CMPStateExpired, CMPActorPKI),
	}
}

// directCMPWorkflow is the synchronous lifecycle: the certificate is issued and
// returned inline in response to the ir/cr/kur.
func directCMPWorkflow(name string) wfxapi.Workflow {
	return assembleCMPWorkflow(name,
		"Lamassu CMP enrollment transaction lifecycle (direct, synchronous issuance)",
		[]string{string(CMPStateReceived), string(CMPStateValidated), string(CMPStateAwaitingPoPResponse), string(CMPStateResponded), string(CMPStateAwaitingCertConf), string(CMPStateRevoking)},
		nil,
		concatTransitions(
			[]wfxapi.Transition{
				cmpEdge(CMPStateReceived, CMPStateValidated, CMPActorPKI),
				cmpEdge(CMPStateReceived, CMPStateRejected, CMPActorPKI),
				cmpEdge(CMPStateValidated, CMPStateResponded, CMPActorPKI),
				cmpEdge(CMPStateValidated, CMPStateRejected, CMPActorPKI),
				cmpEdge(CMPStateValidated, CMPStateIssueFailed, CMPActorPKI),
			},
			popCMPTransitions(),
			postIssuanceCMPTransitions(),
		),
	)
}

// phasedCMPWorkflow is the admin-gated lifecycle: after validation the request
// parks in AwaitingApproval and only an administrator can release it into
// Responded (issuance) or Rejected. Until then the EE receives a "waiting"
// response and polls (RFC 9483 §4.4 / RFC 4210 §5.3.22).
func phasedCMPWorkflow(name string) wfxapi.Workflow {
	return assembleCMPWorkflow(name,
		"Lamassu CMP enrollment transaction lifecycle (phased, admin-approved issuance)",
		[]string{string(CMPStateReceived), string(CMPStateValidated), string(CMPStateAwaitingPoPResponse), string(CMPStateAwaitingApproval), string(CMPStateApproving), string(CMPStateResponded), string(CMPStateAwaitingCertConf), string(CMPStateRevoking)},
		[]wfxapi.State{
			{Name: string(CMPStateAwaitingApproval), Description: "Awaiting administrator approval before issuance"},
			{Name: string(CMPStateApproving), Description: "Administrator decision being applied (approval or rejection in progress)"},
		},
		concatTransitions(
			[]wfxapi.Transition{
				cmpEdge(CMPStateReceived, CMPStateValidated, CMPActorPKI),
				cmpEdge(CMPStateReceived, CMPStateRejected, CMPActorPKI),
				cmpEdge(CMPStateValidated, CMPStateAwaitingApproval, CMPActorPKI),
				cmpEdge(CMPStateValidated, CMPStateRejected, CMPActorPKI),
				// The admin-only gate: only an administrator can approve or reject a
				// parked request. Approving is the transient claim taken while the
				// decision is applied; the sweep recovers a claim that never finished.
				cmpEdge(CMPStateAwaitingApproval, CMPStateApproving, CMPActorAdmin),
				cmpEdge(CMPStateAwaitingApproval, CMPStateRejected, CMPActorAdmin),
				cmpEdge(CMPStateAwaitingApproval, CMPStateExpired, CMPActorPKI),
				cmpEdge(CMPStateApproving, CMPStateResponded, CMPActorAdmin),
				cmpEdge(CMPStateApproving, CMPStateRejected, CMPActorAdmin),
				cmpEdge(CMPStateApproving, CMPStateIssueFailed, CMPActorPKI),
				cmpEdge(CMPStateApproving, CMPStateExpired, CMPActorPKI),
			},
			popCMPTransitions(),
			postIssuanceCMPTransitions(),
		),
	)
}

func concatTransitions(parts ...[]wfxapi.Transition) []wfxapi.Transition {
	var out []wfxapi.Transition
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
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
	if len(transition.Principals) > 0 {
		contextMap["principals"] = append([]string(nil), transition.Principals...)
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

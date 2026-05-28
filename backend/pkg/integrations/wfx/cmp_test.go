package wfx

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	wfxapi "github.com/siemens/wfx/generated/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectCMPWorkflow(t *testing.T) {
	workflow := cmpWorkflowForName(CMPWorkflowNameDirect)

	assert.Equal(t, CMPWorkflowNameDirect, workflow.Name)
	assert.Len(t, workflow.States, 7)
	assert.Len(t, workflow.Transitions, 8)
	assert.Len(t, workflow.Groups, 2)

	actors := map[string]string{}
	for _, transition := range workflow.Transitions {
		assert.Equal(t, wfxapi.WFX, transition.Eligible)
		actors[transition.From+"->"+transition.To] = transition.Description
	}

	// The logical actor is carried in the transition Description.
	assert.Equal(t, CMPActorPKI, actors["Received->Validated"])
	assert.Equal(t, CMPActorPKI, actors["Received->Rejected"])
	assert.Equal(t, CMPActorPKI, actors["Validated->Responded"])
	assert.Equal(t, CMPActorPKI, actors["Responded->AwaitingCertConf"])
	assert.Equal(t, CMPActorPKI, actors["Responded->LogicallyComplete"])
	assert.Equal(t, CMPActorDevice, actors["AwaitingCertConf->Confirmed"])
	assert.Equal(t, CMPActorPKI, actors["AwaitingCertConf->Rejected"])

	// Direct has no approval gate.
	_, hasApproval := actors["Validated->AwaitingApproval"]
	assert.False(t, hasApproval)
}

func TestPhasedCMPWorkflow(t *testing.T) {
	workflow := cmpWorkflowForName(CMPWorkflowNamePhased)

	assert.Equal(t, CMPWorkflowNamePhased, workflow.Name)
	assert.Len(t, workflow.States, 8) // direct + AwaitingApproval
	assert.Len(t, workflow.Transitions, 10)

	actors := map[string]string{}
	for _, transition := range workflow.Transitions {
		assert.Equal(t, wfxapi.WFX, transition.Eligible)
		actors[transition.From+"->"+transition.To] = transition.Description
	}

	// Issuance is gated behind AwaitingApproval; only the admin releases it.
	assert.Equal(t, CMPActorPKI, actors["Validated->AwaitingApproval"])
	assert.Equal(t, CMPActorAdmin, actors["AwaitingApproval->Responded"])
	assert.Equal(t, CMPActorAdmin, actors["AwaitingApproval->Rejected"])
	// Phased never auto-issues straight from Validated.
	_, direct := actors["Validated->Responded"]
	assert.False(t, direct)
}

func TestWorkflowNameFor(t *testing.T) {
	assert.Equal(t, CMPWorkflowNamePhased, WorkflowNameFor(models.CMPWorkflowPhased))
	assert.Equal(t, CMPWorkflowNameDirect, WorkflowNameFor(models.CMPWorkflowDirect))
	assert.Equal(t, CMPWorkflowNameDirect, WorkflowNameFor(""))
}

func TestBuildStatusContext(t *testing.T) {
	contextMap := buildStatusContext(CMPTransition{
		TransactionID:     "deadbeef",
		DMSID:             "dms-1",
		RequestType:       "ir",
		SubjectCommonName: "device-01",
		CertSerialNumber:  "1234",
		Reason:            "duplicate transaction",
		Metadata: map[string]any{
			"bodyTag": 0,
		},
	})

	assert.Equal(t, "deadbeef", contextMap["transactionId"])
	assert.Equal(t, "dms-1", contextMap["dmsId"])
	assert.Equal(t, "ir", contextMap["requestType"])
	assert.Equal(t, "device-01", contextMap["subjectCommonName"])
	assert.Equal(t, "1234", contextMap["certSerialNumber"])
	assert.Equal(t, "duplicate transaction", contextMap["reason"])
	assert.Equal(t, 0, contextMap["bodyTag"])
}

// captureWFXServer is a minimal in-process WFX fake. It records every
// request that lands on it (especially PUT /jobs/{id}/status) so tests can
// assert which transitions actually made it to the wire — guarding against
// silent short-circuits in the reporter.
type captureWFXServer struct {
	mu       sync.Mutex
	server   *httptest.Server
	statuses []capturedStatus
}

type capturedStatus struct {
	JobID   string
	State   string
	Message string
	Context map[string]any
}

func newCaptureWFXServer(t *testing.T) *captureWFXServer {
	t.Helper()
	c := &captureWFXServer{}
	mux := http.NewServeMux()

	// Helper: WFX's generated client only populates the typed JSON200 field
	// when the response Content-Type is application/json — without it, the
	// client reports HTTP 200 but JSON200 is nil and the reporter treats it
	// as a failure.
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}

	// Workflow lookup: pretend the workflow already exists so ensureWorkflow
	// is a no-op. Returning 200 with a minimal Workflow body is enough.
	mux.HandleFunc("/api/wfx/v1/workflows/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, wfxapi.Workflow{Name: DefaultCMPWorkflowName})
	})

	// Job lookup: return empty content so ensureJob falls through to creation.
	mux.HandleFunc("/api/wfx/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, wfxapi.PaginatedJobList{Content: []wfxapi.Job{}})
			return
		}
		// POST: create a job. We return a fully-formed Job with state=Received
		// so the reporter's "freshly-created job" path is exercised.
		var req wfxapi.PostJobsJSONRequestBody
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, http.StatusCreated, wfxapi.Job{
			ID:         "job-fixture-1",
			ClientID:   req.ClientID,
			Definition: req.Definition,
			Status: &wfxapi.JobStatus{
				State: string(CMPStateReceived),
			},
		})
	})

	// PUT /api/wfx/v1/jobs/{id}/status — the call we want to capture.
	mux.HandleFunc("/api/wfx/v1/jobs/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/status") {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req wfxapi.PutJobsIdStatusJSONRequestBody
		_ = json.Unmarshal(body, &req)
		segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/wfx/v1/jobs/"), "/")
		var capturedCtx map[string]any
		if req.Context != nil {
			capturedCtx = *req.Context
		}
		c.mu.Lock()
		c.statuses = append(c.statuses, capturedStatus{
			JobID:   segs[0],
			State:   req.State,
			Message: req.Message,
			Context: capturedCtx,
		})
		c.mu.Unlock()
		writeJSON(w, http.StatusOK, wfxapi.Job{
			ID:     segs[0],
			Status: &wfxapi.JobStatus{State: req.State},
		})
	})

	c.server = httptest.NewServer(mux)
	t.Cleanup(c.server.Close)
	return c
}

func (c *captureWFXServer) findStatusUpdate(state CMPState) *capturedStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.statuses {
		if c.statuses[i].State == string(state) {
			return &c.statuses[i]
		}
	}
	return nil
}

func newCaptureReporter(t *testing.T, server *captureWFXServer) *cmpReporter {
	t.Helper()
	client, err := wfxapi.NewClientWithResponses(server.server.URL+"/api/wfx/v1", wfxapi.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	require.NoError(t, err)
	r := &cmpReporter{
		client:          client,
		logger:          logrus.NewEntry(logrus.New()),
		workflowName:     DefaultCMPWorkflowName,
		timeout:          5 * time.Second,
		ensuredWorkflows: map[string]struct{}{DefaultCMPWorkflowName: {}}, // skip ensureWorkflow; the test fake answers anyway
	}
	return r
}

// TestEmit_ReceivedState_PushesMetadata is the regression guard for the bug
// where the reporter short-circuited the FIRST PUT /status call on
// freshly-created jobs (which happened to always start in CMPStateReceived).
// The effect was that the inbound IR/CR/KUR DER (cmpRequestB64) was passed
// to Emit but never persisted in the WFX history — so the dashboard's
// per-snapshot ASN.1 viewer had no payload to show on the Received state.
//
// The test asserts that the PUT /status call IS made AND that the captured
// context contains the cmpRequestB64 key forwarded from the transition's
// Metadata map.
func TestEmit_ReceivedState_PushesMetadata(t *testing.T) {
	server := newCaptureWFXServer(t)
	reporter := newCaptureReporter(t, server)

	const sampleIRBase64 = "deadbeefdeadbeef" // any non-empty string; we only check the value round-trips.
	jobID, err := reporter.Emit(context.Background(), CMPTransition{
		TransactionID:     "tx-abc-123",
		DMSID:             "dms-1",
		RequestType:       "ir",
		SubjectCommonName: "device-01",
		State:             CMPStateReceived,
		Metadata: map[string]any{
			"bodyTag":       0,
			"cmpRequestB64": sampleIRBase64,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "job-fixture-1", jobID)

	got := server.findStatusUpdate(CMPStateReceived)
	require.NotNil(t, got, "Received transition with metadata MUST trigger a PUT /jobs/{id}/status — otherwise the IR DER is lost")
	assert.Equal(t, "tx-abc-123", got.Context["transactionId"])
	assert.Equal(t, "ir", got.Context["requestType"])
	assert.Equal(t, sampleIRBase64, got.Context["cmpRequestB64"],
		"cmpRequestB64 MUST round-trip into the Received state's context so the dashboard can decode it")
}

// TestEmit_ReceivedState_NoMetadataSkipsPush — counterpart to the test
// above: when the Received transition has no diagnostic payload, the
// same-state suppression should still skip the PUT (job is created in
// Received state already, no point re-PUTing nothing).
func TestEmit_ReceivedState_NoMetadataSkipsPush(t *testing.T) {
	server := newCaptureWFXServer(t)
	reporter := newCaptureReporter(t, server)

	_, err := reporter.Emit(context.Background(), CMPTransition{
		TransactionID:     "tx-empty",
		SubjectCommonName: "device-empty",
		State:             CMPStateReceived,
	})
	require.NoError(t, err)

	assert.Nil(t, server.findStatusUpdate(CMPStateReceived),
		"empty Received transition should be suppressed (job is already in Received)")
}

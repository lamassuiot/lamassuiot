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
	wfxworkflow "github.com/siemens/wfx/workflow"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectCMPWorkflow(t *testing.T) {
	workflow := cmpWorkflowForName(CMPWorkflowNameDirect)

	assert.Equal(t, CMPWorkflowNameDirect, workflow.Name)
	assert.Len(t, workflow.States, 12)
	assert.Len(t, workflow.Transitions, 19)
	assert.Len(t, workflow.Groups, 3)

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
	assert.Equal(t, CMPActorPKI, actors["Validated->IssueFailed"])

	// Proof-of-possession round trip: the device answers the challenge.
	assert.Equal(t, CMPActorPKI, actors["Validated->AwaitingPoPResponse"])
	assert.Equal(t, CMPActorDevice, actors["AwaitingPoPResponse->Responded"])
	assert.Equal(t, CMPActorPKI, actors["AwaitingPoPResponse->Expired"])

	// Confirmation-timeout revocation is the PKI's; revocation requests come
	// from the device (rr) or an administrator.
	assert.Equal(t, CMPActorPKI, actors["AwaitingCertConf->Revoking"])
	assert.Equal(t, CMPActorPKI, actors["Revoking->Revoked"])
	// No way back from Revoking: WFX rejects cyclic workflows.
	_, rollback := actors["Revoking->AwaitingCertConf"]
	assert.False(t, rollback)
	assert.Equal(t, "device, admin", actors["AwaitingCertConf->Revoked"])
	assert.Equal(t, "device, admin", actors["Confirmed->Revoked"])
	assert.Equal(t, "device, admin", actors["LogicallyComplete->Revoked"])

	// Direct has no approval gate.
	_, hasApproval := actors["Validated->AwaitingApproval"]
	assert.False(t, hasApproval)
}

func TestPhasedCMPWorkflow(t *testing.T) {
	workflow := cmpWorkflowForName(CMPWorkflowNamePhased)

	assert.Equal(t, CMPWorkflowNamePhased, workflow.Name)
	assert.Len(t, workflow.States, 14) // direct + AwaitingApproval + Approving
	assert.Len(t, workflow.Transitions, 25)

	actors := map[string]string{}
	for _, transition := range workflow.Transitions {
		assert.Equal(t, wfxapi.WFX, transition.Eligible)
		actors[transition.From+"->"+transition.To] = transition.Description
	}

	// Issuance is gated behind AwaitingApproval; only the admin releases it.
	assert.Equal(t, CMPActorPKI, actors["Validated->AwaitingApproval"])
	assert.Equal(t, CMPActorAdmin, actors["AwaitingApproval->Approving"])
	assert.Equal(t, CMPActorAdmin, actors["AwaitingApproval->Rejected"])
	assert.Equal(t, CMPActorPKI, actors["AwaitingApproval->Expired"])
	assert.Equal(t, CMPActorAdmin, actors["Approving->Responded"])
	assert.Equal(t, CMPActorAdmin, actors["Approving->Rejected"])
	assert.Equal(t, CMPActorPKI, actors["Approving->IssueFailed"])
	// Only the admin releases a parked request: there is no direct jump.
	_, jump := actors["AwaitingApproval->Responded"]
	assert.False(t, jump)
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
		Principals:        []string{"admin-a", "admin-b"},
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
	assert.Equal(t, []string{"admin-a", "admin-b"}, contextMap["principals"])
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
		client:           client,
		logger:           logrus.NewEntry(logrus.New()),
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

// TestEmit_NoWorkflow_FindsJobInPhasedWorkflow guards the confirmation
// monitor's Rejected emission, which carries no Workflow: the job lives in the
// phased workflow, so the reporter must find it there instead of opening an
// orphan job in the default (direct) workflow and leaving the real one in
// AwaitingCertConf.
func TestEmit_NoWorkflow_FindsJobInPhasedWorkflow(t *testing.T) {
	var (
		mu      sync.Mutex
		created int
		puts    []string
	)
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/wfx/v1/workflows/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, wfxapi.Workflow{Name: CMPWorkflowNamePhased})
	})
	mux.HandleFunc("/api/wfx/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost {
			created++
			writeJSON(w, http.StatusCreated, wfxapi.Job{ID: "orphan"})
			return
		}
		content := []wfxapi.Job{}
		if r.URL.Query().Get("workflow") == CMPWorkflowNamePhased {
			content = append(content, wfxapi.Job{
				ID:         "job-phased",
				Definition: map[string]any{"transactionId": "tx-1"},
				Status:     &wfxapi.JobStatus{State: string(CMPStateAwaitingCertConf)},
			})
		}
		writeJSON(w, http.StatusOK, wfxapi.PaginatedJobList{Content: content})
	})
	mux.HandleFunc("/api/wfx/v1/jobs/", func(w http.ResponseWriter, r *http.Request) {
		var req wfxapi.PutJobsIdStatusJSONRequestBody
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/wfx/v1/jobs/"), "/")[0]
		mu.Lock()
		puts = append(puts, id+":"+req.State)
		mu.Unlock()
		writeJSON(w, http.StatusOK, wfxapi.Job{ID: id, Status: &wfxapi.JobStatus{State: req.State}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, err := wfxapi.NewClientWithResponses(srv.URL+"/api/wfx/v1", wfxapi.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	require.NoError(t, err)
	reporter := &cmpReporter{
		client:       client,
		logger:       logrus.NewEntry(logrus.New()),
		workflowName: DefaultCMPWorkflowName,
		timeout:      5 * time.Second,
		ensuredWorkflows: map[string]struct{}{
			CMPWorkflowNameDirect: {},
			CMPWorkflowNamePhased: {},
		},
	}

	jobID, err := reporter.Emit(context.Background(), CMPTransition{
		TransactionID:     "tx-1",
		SubjectCommonName: "device-01",
		State:             CMPStateRejected,
		Reason:            "certConf wait time expired",
	})
	require.NoError(t, err)
	assert.Equal(t, "job-phased", jobID)

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, created, "no orphan job may be created in the default workflow")
	assert.Equal(t, []string{"job-phased:" + string(CMPStateRejected)}, puts)
}

// TestCMPWorkflows_Consistency guards the single state vocabulary: every state
// a transition or group names is defined by the workflow, every persisted
// transaction state exists in WFX under the same name, and the workflow's
// initial state comes first.
func TestCMPWorkflows_Consistency(t *testing.T) {
	persisted := []models.CMPTransactionState{
		models.CMPTransactionStateAwaitingPoPResponse,
		models.CMPTransactionStateAwaitingApproval,
		models.CMPTransactionStateApproving,
		models.CMPTransactionStateAwaitingCertConf,
		models.CMPTransactionStateLogicallyComplete,
		models.CMPTransactionStateConfirmed,
		models.CMPTransactionStateRevoking,
		models.CMPTransactionStateRevoked,
		models.CMPTransactionStateRejected,
		models.CMPTransactionStateIssueFailed,
		models.CMPTransactionStateExpired,
	}

	for _, name := range []string{CMPWorkflowNameDirect, CMPWorkflowNamePhased} {
		workflow := cmpWorkflowForName(name)

		// WFX validates every workflow it is asked to create (unique states,
		// non-overlapping groups, exactly one initial state, no cycles); a
		// definition it rejects makes every transition export fail with HTTP 400.
		require.NoError(t, wfxworkflow.ValidateWorkflow(&workflow), "%s must pass WFX's own validation", name)

		defined := map[string]bool{}
		for _, state := range workflow.States {
			defined[state.Name] = true
		}
		require.NotEmpty(t, workflow.States)
		assert.Equal(t, string(CMPStateReceived), workflow.States[0].Name, "%s: initial state must come first", name)

		for _, transition := range workflow.Transitions {
			assert.True(t, defined[transition.From], "%s: transition from undefined state %q", name, transition.From)
			assert.True(t, defined[transition.To], "%s: transition to undefined state %q", name, transition.To)
		}
		for _, group := range workflow.Groups {
			for _, state := range group.States {
				assert.True(t, defined[state], "%s: group %s names undefined state %q", name, group.Name, state)
			}
		}

		for _, state := range persisted {
			// AwaitingApproval/Approving only exist in the phased workflow.
			if name == CMPWorkflowNameDirect && (state == CMPStateAwaitingApproval || state == CMPStateApproving) {
				continue
			}
			assert.True(t, defined[string(state)], "%s: persisted state %q missing from the workflow", name, state)
		}
	}
}

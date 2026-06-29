package wfx

import (
	"testing"

	wfxapi "github.com/siemens/wfx/generated/api"
	"github.com/stretchr/testify/assert"
)

func TestDefaultCMPWorkflow(t *testing.T) {
	workflow := defaultCMPWorkflow("test.workflow")

	assert.Equal(t, "test.workflow", workflow.Name)
	assert.Len(t, workflow.States, 10)
	assert.Len(t, workflow.Transitions, 12)
	assert.Len(t, workflow.Groups, 2)

	edges := map[string]wfxapi.EligibleEnum{}
	for _, transition := range workflow.Transitions {
		edges[transition.From+"->"+transition.To] = transition.Eligible
	}

	assert.Equal(t, wfxapi.WFX, edges["Received->Parsed"])
	assert.Equal(t, wfxapi.WFX, edges["Parsed->Rejected"])
	assert.Equal(t, wfxapi.WFX, edges["Validated->Issuing"])
	assert.Equal(t, wfxapi.WFX, edges["Issued->Responded"])
	assert.Equal(t, wfxapi.WFX, edges["Responded->AwaitingCertConf"])
	assert.Equal(t, wfxapi.WFX, edges["Responded->LogicallyComplete"])
	assert.Equal(t, wfxapi.WFX, edges["AwaitingCertConf->Confirmed"])
	assert.Equal(t, wfxapi.WFX, edges["AwaitingCertConf->Rejected"])
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

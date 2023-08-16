package models

type IotAWSAccountInfo struct {
	AccountID       string
	IotMQTTEndpoint string
}

type CAIoTAWSRegistration struct {
	Register                  bool     `json:"register"`
	JITP                      bool     `json:"jitp"`
	JITPName                  string   `json:"jitp_name"`
	JITPGroupName             string   `json:"jitp_group_name"`
	JITPInlinePolicy          string   `json:"jitp_inline_policy"`
	JITPExternalPoliciesNames []string `json:"jitp_external_policy_names"`
}

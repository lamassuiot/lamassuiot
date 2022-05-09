package cloudproviders

import "errors"

type CloudProvider int
type ConsistencyStatus int

const (
	CloudProvider_AmazonWebServices CloudProvider = iota
	CloudProvider_MicrosoftAzure
	CloudProvider_GoogleCloud
)

const (
	ConsistencyStatus_Disabled ConsistencyStatus = iota
	ConsistencyStatus_Consistent
	ConsistencyStatus_Inconsistent
)

func (c ConsistencyStatus) String() string {
	switch c {
	case ConsistencyStatus_Disabled:
		return "DISABLED"
	case ConsistencyStatus_Consistent:
		return "CONSISTENT"
	case ConsistencyStatus_Inconsistent:
		return "INCONSISTENT"
	default:
		return ""
	}
}

func ParseCloudProviderType(s string) (CloudProvider, error) {
	switch s {
	case "aws":
		return CloudProvider_AmazonWebServices, nil
	case "azure":
		return CloudProvider_MicrosoftAzure, nil
	case "gcloud":
		return CloudProvider_GoogleCloud, nil
	default:
		return -1, errors.New("unsupported cloud provider type: " + s)
	}
}

type CloudConnector struct {
	CloudProvider   string           `json:"cloud_provider"`
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Status          string           `json:"status"`
	IP              string           `json:"ip"`
	Port            string           `json:"port"`
	SynchronizedCAs []SynchronizedCA `json:"synchronized_cas"`
	Configuration   interface{}      `json:"cloud_configuration"`
}

type DatabaseSynchronizedCA struct {
	CloudConnectorID string `json:"cloud_connector_id"`
	CAName           string `json:"ca_name"`
	SerialNumber     string `json:"serial_number"`
	EnabledTimestamp string `json:"enabled"`
}

type SynchronizedCA struct {
	CAName              string      `json:"ca_name"`
	SerialNumber        string      `json:"serial_number"`
	EnabledTimestamp    string      `json:"enabled"`
	ConsistencyStatus   string      `json:"consistency_status"`
	CloudProviderConfig interface{} `json:"config,omitempty"`
}

type CloudProviderCAConfig struct {
	CAName string      `json:"ca_name"`
	Config interface{} `json:"config"`
}
type CaConfig struct {
	ARN            string `json:"ARN"`
	CertificateID  string `json:"CertificateID"`
	CreationDate   string `json:"CreationDate"`
	CAName         string `json:"CAName"`
	Status         string `json:"Status"`
	PolicyStatus   string `json:"PolicyStatus"`
	PolicyDocumnet string `json:"PolicyDocumnet"`
}

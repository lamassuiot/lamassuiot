package awslambda

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	log "github.com/sirupsen/logrus"

	"encoding/json"

	"github.com/lamassuiot/lamassuiot/pkg/remfuncs"
)

type awsLambdaEngine struct {
	session *session.Session
}

func NewAWSLambdaFuncEngineinterface(session *session.Session) remfuncs.PluggableFunctionEngine {
	return &awsLambdaEngine{
		session: session,
	}
}

func (a *awsLambdaEngine) RunFunction(funcID string, input any) (interface{}, error) {

	client := lambda.New(a.session)

	payload, err := json.Marshal(input)
	if err != nil {
		log.Errorf("Error marshalling %s request", funcID)
		return nil, err
	}

	result, err := client.Invoke(&lambda.InvokeInput{FunctionName: aws.String(funcID), Payload: payload})
	if err != nil {
		log.Errorf("Error calling %s", funcID)
		return nil, err
	}

	var resp map[string]interface{}

	strResp := string(result.Payload)
	json.Unmarshal([]byte(strResp), &resp)

	if err != nil {
		log.Errorf("Error unmarshalling %s response", funcID)
		return nil, err
	}

	// // If the status code is NOT 200, the call failed
	// if resp.StatusCode != 200 {
	// 	log.Errorf("Error getting items, StatusCode: " + strconv.Itoa(resp.StatusCode))
	// 	os.Exit(0)
	// }

	// // If the result is failure, we got an error
	// if resp.Body.Result == "failure" {
	// 	log.Errorf("Failed to get items")
	// 	os.Exit(0)
	// }

	// // Print out items
	// if len(resp.Body.Data) > 0 {
	// 	for i := range resp.Body.Data {
	// 		log.Errorf(resp.Body.Data[i].Item)
	// 	}
	// } else {
	// 	log.Errorf("There were no items")
	// }

	return resp, err
}

// Due to go plugin mechanism,
// the package of function handler must be main package
package main

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

var AUTHORIZE string = `{"authorized": true}`
var NOT_AUTHORIZE string = `{"authorized": false}`

// Handler is the entry point for this fission function
func Handler(w http.ResponseWriter, r *http.Request) {
	l := helpers.SetupLogger(config.Trace, "service", "lambda")

	l.Info("Request received")

	bodyBytes := new(bytes.Buffer)
	_, err := bodyBytes.ReadFrom(r.Body)
	if err != nil {
		l.Error("Error reading request body: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	l.Tracef("Request body: %s", bodyBytes.String())

	var request map[string]interface{}
	err = json.Unmarshal(bodyBytes.Bytes(), &request)
	if err != nil {
		l.Error("Error decoding request body: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	httpRequest, ok := request["http_request"].(map[string]interface{})
	if !ok {
		l.Error("Error getting headers from request")
		http.Error(w, "Error getting headers from request", http.StatusBadRequest)
		return
	}

	enrollHeaders, ok := httpRequest["headers"].(map[string]interface{})
	if !ok {
		l.Error("Error getting enroll headers from request")
		http.Error(w, "Error getting enroll headers from request", http.StatusBadRequest)
		return
	}

	deviceCN := request["device_cn"].(string)

	l.Infof("Device CN: %s", deviceCN)
	l.Infof("Enroll Headers: %v", enrollHeaders)

	// // Call Sandgrain API to authorize the device

	w.Write([]byte(AUTHORIZE))
}

Lamassu IoT
===================
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](http://www.mozilla.org/MPL/2.0/index.txt)

<img src="https://www.lamassu.io/assets/brand/lamassu-brand.png" alt="Lamassu App" title="Lamassu" />

Lamassu is an IoT first PKI designed for industrial scenarios. This is the main code repository for Lamassu IoT where the product logic is being implemented. If you are looking for deployment instructions, please check the [docs](https://www.lamassu.io/docs/) or the project's [Docker Compose repository](https://github.com/lamassuiot/lamassu-compose).

## Using the GO clients

Lamassu provides easy to use GO clients for most of its APIs to help speeding up the development of aplications:

```go
package main

import (
  "net/url"
  lamassuCAClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
  caDTO "github.com/lamassuiot/lamassuiot/pkg/ca/common/dto"
  "github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

function main (){
    lamassuGatewayURL := "dev.lamassu.io"
    apiCAFile := "path/to/apigw.crt"
    
    caClient := lamassuCAClient.NewLamassuCAClient(client.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   lamassuGatewayURL,
			Path:   "/api/ca/",
		},
		AuthMethod: client.JWT,
		AuthMethodConfig: &client.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: "https",
				Host:   "auth." + lamassuGatewayURL,
			},
			CACertificate: apiCAFile,
		},
		CACertificate: apiCAFile,
	})
    
    ca, err = caClient.CreateCA(context.Background(), caDTO.Pki, caName, caDTO.PrivateKeyMetadata{KeyType: "rsa", KeyBits: 2048}, caDTO.Subject{CN: caName}, 365*time.Hour, 30*time.Hour)
}


```


## Running Unit tests

```
#For pretty printing
go install github.com/haveyoudebuggedit/gotestfmt/v2/cmd/gotestfmt@v2.3.1


go test -json -v ./pkg/ca/server/api/service/ | gotestfmt
go test -json -v ./pkg/dms-enroller/server/api/service/ | gotestfmt
go test -json -v ./pkg/device-manager/server/api/service/ | gotestfmt
```

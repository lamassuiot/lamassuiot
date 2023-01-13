package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/jakehl/goid"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
)

var failedOps uint64

func main() {
	var maxGoRoutines int
	flag.IntVar(&maxGoRoutines, "max-go-routines", 1, "Max Go Routines")

	var cas int
	flag.IntVar(&cas, "cas", 1000, "CAs to create per thread")

	var gatewayURL string
	flag.StringVar(&gatewayURL, "gateway-url", "https://pre.lamassu.zpd.ikerlan.es", "gateway URL")

	flag.Parse()

	fmt.Println("===== CA Stress test ====")
	fmt.Printf("max-go-routines: %d\n", maxGoRoutines)
	fmt.Printf("cas: %d\n", cas)
	fmt.Printf("gatewayURL-url: %s\n", gatewayURL)

	if gatewayURL == "" {
		fmt.Printf("gateway URL cannot be empty. Exiting")
		os.Exit(1)
	}

	parsedGatewayURL, err := url.Parse(gatewayURL)
	if err != nil {
		fmt.Printf("Error while parsing gateway URL. Exiting: %s", err)
		os.Exit(1)
	}

	fmt.Println("\nstarting ...")

	var caClient lamassucaclient.LamassuCAClient
	caClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: parsedGatewayURL.Scheme,
			Host:   parsedGatewayURL.Host,
			Path:   "/api/ca",
		},
		AuthMethod: clientUtils.AuthMethodJWT,
		AuthMethodConfig: &clientUtils.JWTConfig{
			Username: "enroller",
			Password: "enroller",
			URL: &url.URL{
				Scheme: parsedGatewayURL.Scheme,
				Host:   "auth." + parsedGatewayURL.Host,
			},
			Insecure: true,
		},
		Insecure: true,
	})
	if err != nil {
		fmt.Printf("Could not create LamassuCA client. Exiting: %s", err)
		os.Exit(1)
	}

	jobs := make(chan int, cas)
	results := make(chan int, cas)

	for w := 0; w < maxGoRoutines; w++ {
		go worker(jobs, results, caClient)
	}

	for i := 0; i < cas; i++ {
		jobs <- 1
	}
	close(jobs)

	for a := 1; a <= cas; a++ {
		<-results
	}

	fmt.Println("ops:", cas)
	fmt.Println("failedOps:", failedOps)
	fmt.Printf("failedOps: %d%s\n", failedOps*100/uint64(cas), "%")

	fmt.Println("Done")

}

func worker(queue <-chan int, results chan<- int, caClient lamassucaclient.LamassuCAClient) {
	for range queue {
		cn := fmt.Sprintf("CA-%s", goid.NewV4UUID().String())
		out, err := caClient.CreateCA(context.Background(), &api.CreateCAInput{
			CAType: api.CATypePKI,
			Subject: api.Subject{
				CommonName: cn,
			},
			KeyMetadata: api.KeyMetadata{
				KeyType: api.RSA,
				KeyBits: 4096,
			},
			CADuration:       time.Hour * 2,
			IssuanceDuration: time.Hour,
		})

		if err != nil {
			fmt.Printf("Could not create CA [%s]: %s\n", cn, err)
			atomic.AddUint64(&failedOps, 1)
		} else {
			fmt.Printf("CA created: %s - %s\n", cn, out.SerialNumber)
		}

		results <- 1
	}
}

// test-webhook is a standalone HTTP server that simulates an external enrollment
// authorization webhook. It is intended for local manual testing of the
// EXTERNAL_WEBHOOK auth mode in Lamassu DMS.
//
// Usage:
//
//	go run ./backend/cmd/test-webhook [flags]
//
// Flags:
//
//	-port      int     Port to listen on (default 8090)
//	-mode      string  Authorization mode: allow | deny | apikey (default "allow")
//	-header    string  Header name to check when mode=apikey (default "X-API-Key")
//	-key       string  Expected header value when mode=apikey (default "secret")
//	-verbose   bool    Print full decoded payload for every request (default true)
//
// The server exposes:
//
//	POST /verify   — enrollment auth endpoint (configure this URL in the DMS)
//	GET  /config   — shows current runtime configuration
package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

// enrollWebhookPayload is the JSON body sent by Lamassu to the webhook.
type enrollWebhookPayload struct {
	CSR      string                 `json:"csr"`
	APS      string                 `json:"aps"`
	DeviceCN string                 `json:"device_cn"`
	HTTP     enrollWebhookHTTPField `json:"http_request"`
}

type enrollWebhookHTTPField struct {
	Headers map[string]string `json:"headers"`
	URL     string            `json:"url"`
}

// webhookResponse is the JSON body returned to Lamassu.
type webhookResponse struct {
	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason,omitempty"`
}

var (
	port    int
	mode    string
	header  string
	key     string
	verbose bool
)

func main() {
	flag.IntVar(&port, "port", 8090, "Port to listen on")
	flag.StringVar(&mode, "mode", "allow", "Authorization mode: allow | deny | apikey")
	flag.StringVar(&header, "header", "X-API-Key", "Header name to check (mode=apikey)")
	flag.StringVar(&key, "key", "secret", "Expected header value (mode=apikey)")
	flag.BoolVar(&verbose, "verbose", true, "Print full decoded CSR details")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", handleVerify)
	mux.HandleFunc("GET /config", handleConfig)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("=======================================================")
	log.Printf("  Lamassu test enrollment webhook server")
	log.Printf("  Listening : http://localhost%s", addr)
	log.Printf("  Mode      : %s", mode)
	if mode == "apikey" {
		log.Printf("  Header    : %s", header)
		log.Printf("  Key       : %s", key)
	}
	log.Printf("  Endpoint  : POST http://localhost%s/verify", addr)
	log.Printf("=======================================================")
	log.Printf("")
	log.Printf("Configure the DMS webhook URL to: http://localhost%s/verify", addr)
	log.Printf("")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %s", err)
	}
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	ts := time.Now().Format("15:04:05.000")

	var payload enrollWebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("[%s] ERROR — could not decode request body: %s", ts, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(webhookResponse{Authorized: false, Reason: "invalid JSON body"})
		return
	}

	log.Printf("[%s] ─────────────────── Enrollment Request ───────────────────", ts)
	log.Printf("[%s]   APS (DMS ID) : %s", ts, payload.APS)
	log.Printf("[%s]   Device CN    : %s", ts, payload.DeviceCN)
	log.Printf("[%s]   Request URL  : %s", ts, payload.HTTP.URL)

	if verbose {
		log.Printf("[%s]   Headers:", ts)
		for k, v := range payload.HTTP.Headers {
			log.Printf("[%s]     %s: %s", ts, k, v)
		}

		if payload.CSR != "" {
			csrPEM, err := base64.StdEncoding.DecodeString(payload.CSR)
			if err == nil {
				block, _ := pem.Decode(csrPEM)
				if block != nil {
					log.Printf("[%s]   CSR PEM type : %s (%d bytes)", ts, block.Type, len(block.Bytes))
				}
			}
		}
	}

	authorized, reason := authorize(r, &payload)

	log.Printf("[%s]   ──────────────────────────────────────────────────────────", ts)
	if authorized {
		log.Printf("[%s]   DECISION: ✓ AUTHORIZED", ts)
	} else {
		log.Printf("[%s]   DECISION: ✗ DENIED — %s", ts, reason)
	}
	log.Printf("[%s] ─────────────────────────────────────────────────────────────", ts)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(webhookResponse{Authorized: authorized, Reason: reason})
}

func authorize(r *http.Request, payload *enrollWebhookPayload) (bool, string) {
	switch mode {
	case "allow":
		return true, ""

	case "deny":
		return false, "webhook configured to deny all requests"

	case "apikey":
		// The original request headers are forwarded inside the JSON payload.
		// Lamassu puts them in payload.HTTP.Headers. We check there first,
		// then also check the direct request header as a fallback.
		got, ok := payload.HTTP.Headers[header]
		if !ok {
			got = r.Header.Get(header)
		}
		if got == "" {
			return false, fmt.Sprintf("missing header %q", header)
		}
		if got != key {
			return false, fmt.Sprintf("invalid value for header %q", header)
		}
		return true, ""

	default:
		return false, fmt.Sprintf("unknown mode %q", mode)
	}
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := map[string]any{
		"mode":    mode,
		"port":    port,
		"verbose": verbose,
	}
	if mode == "apikey" {
		cfg["header"] = header
		cfg["key"] = key
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

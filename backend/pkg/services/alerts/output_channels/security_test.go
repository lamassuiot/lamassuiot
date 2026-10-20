package outputchannels

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	lconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func notificationTestEvent() cloudevents.Event {
	e := cloudevents.NewEvent()
	e.SetID("security-test")
	e.SetSource("test")
	e.SetType("test.event")
	return e
}

func notificationTestService(t *testing.T, kind models.ChannelType, url string, options *models.WebhookCallHttpClient) NotificationSenderService {
	t.Helper()
	// Exercise JSON configuration decoding as it is used for stored channels.
	payload := map[string]any{"webhook_url": url, "webhook_method": "POST"}
	if options != nil {
		payload["http_client"] = options
	}
	svc, err := GetOutputService(models.Channel{Type: kind, Name: "test", Config: payload}, lconfig.SMTPServer{})
	require.NoError(t, err)
	return svc
}

func TestNotificationChannelsRejectUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("notification reached a server with an untrusted certificate")
	}))
	defer server.Close()
	for _, kind := range []models.ChannelType{models.ChannelTypeWebhook, models.ChannelTypeMSTeams} {
		t.Run(string(kind), func(t *testing.T) {
			for _, options := range []*models.WebhookCallHttpClient{nil, {ValidateServerCert: false}} {
				svc := notificationTestService(t, kind, server.URL, options)
				err := svc.SendNotification(logrus.NewEntry(logrus.New()), context.Background(), notificationTestEvent())
				var unknownAuthority x509.UnknownAuthorityError
				require.ErrorAs(t, err, &unknownAuthority)
			}
		})
	}
}

func TestNotificationChannelsSendConfiguredAuthentication(t *testing.T) {
	for _, kind := range []models.ChannelType{models.ChannelTypeWebhook, models.ChannelTypeMSTeams} {
		t.Run(string(kind), func(t *testing.T) {
			requests := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Header.Get("X-API-Key")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			options := &models.WebhookCallHttpClient{AuthMode: config.ApiKey, ApiKey: models.WebhookCallHttpClientApiKey{Header: "X-API-Key", Key: "test-secret"}}
			svc := notificationTestService(t, kind, server.URL, options)
			require.NoError(t, svc.SendNotification(logrus.NewEntry(logrus.New()), context.Background(), notificationTestEvent()))
			require.Equal(t, "test-secret", <-requests)
		})
	}
}

func TestNotificationChannelsRejectUnknownAuthentication(t *testing.T) {
	for _, kind := range []models.ChannelType{models.ChannelTypeWebhook, models.ChannelTypeMSTeams} {
		svc := notificationTestService(t, kind, "http://127.0.0.1:1", &models.WebhookCallHttpClient{AuthMode: "invalid"})
		err := svc.SendNotification(logrus.NewEntry(logrus.New()), context.Background(), notificationTestEvent())
		require.ErrorContains(t, err, "unsupported notification authentication mode")
	}
}

func TestEmailEscapesEventHTML(t *testing.T) {
	event := notificationTestEvent()
	event.SetType(`<img src=x onerror=alert(1)>`)
	require.NoError(t, event.SetData(cloudevents.ApplicationJSON, map[string]string{"value": `</pre><script>alert(1)</script>`}))
	svc := &SMTPOutputService{config: models.EmailConfig{Email: "to@example.com"}, smtpServer: lconfig.SMTPServer{From: "from@example.com"}}
	message, err := svc.buildMessage(event)
	require.NoError(t, err)
	var wire bytes.Buffer
	_, err = message.WriteTo(&wire)
	require.NoError(t, err)
	parsed, err := mail.ReadMessage(&wire)
	require.NoError(t, err)
	body, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	require.NoError(t, err)
	require.Contains(t, string(body), "&lt;")
	require.NotContains(t, string(body), "<img src=x")
	require.NotContains(t, string(body), "<Img")
	require.NotContains(t, string(body), "<script>")
	require.Contains(t, string(body), `\u003c/pre\u003e`)
	require.Contains(t, string(body), `<pre class="json-container">`)
}

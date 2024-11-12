package outputchannels

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/gomail.v2"
)

type SMTPOutputService struct {
	config     models.EmailConfig
	smtpServer config.SMTPServer
}

func NewSMTPOutputService(config models.EmailConfig, smtpServer config.SMTPServer) NotificationSenderService {
	return &SMTPOutputService{
		config:     config,
		smtpServer: smtpServer,
	}
}

func (s *SMTPOutputService) SendNotification(ctx context.Context, event cloudevents.Event) error {
	humanEventNameFormat := cases.Title(language.Und).String(strings.Join(strings.Split(event.Type(), "."), " "))

	t := template.New("eventmail")
	t, err := t.Parse(emailTemplate)
	if err != nil {
		return err
	}

	eventBytes, err := event.MarshalJSON()
	if err != nil {
		return err
	}

	var eventMap map[string]any
	json.Unmarshal(eventBytes, &eventMap)
	eventBytes, _ = json.MarshalIndent(eventMap, "", "  ")

	templateData := struct {
		EventName  string
		CloudEvent string
		Time       string
		Date       string
	}{
		EventName:  humanEventNameFormat,
		CloudEvent: string(eventBytes),
		Time:       fmt.Sprintf("%d:%d", event.Time().Hour(), event.Time().Minute()),
		Date:       fmt.Sprintf("%d/%d/%d", event.Time().Day(), event.Time().Month(), event.Time().Year()),
	}

	eventBodyBuf := new(bytes.Buffer)
	if err = t.Execute(eventBodyBuf, templateData); err != nil {
		return err
	}

	msg := gomail.NewMessage()
	msg.SetHeader("From", s.smtpServer.From)
	msg.SetHeader("To", s.config.Email)
	msg.SetHeader("Subject", fmt.Sprintf("Lamassu Event: %s", humanEventNameFormat))
	msg.SetBody("text/html", eventBodyBuf.String())
	n := gomail.NewDialer(s.smtpServer.Host, s.smtpServer.Port, s.smtpServer.Username, s.smtpServer.Password)
	if s.smtpServer.Insecure {
		n.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if !s.smtpServer.SSL {
		n.SSL = false
	}

	// Send the email
	if err := n.DialAndSend(msg); err != nil {
		return err
	}
	return nil
}

const emailTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Your Email Title</title>
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #000000;
        }
        .pre-header{
            padding: 20px 50px;
        }
        .header {
            background-color: #3700FF;
            color: #ffffff;
            padding: 24px 30px;           
        }
        .header-title {
            margin: 0;
        }
        .date {
            color: #00D05F;
            font-weight: bold;
            text-align: right;
        }
        .content {
            padding: 20px;
            color: #ffffff;
        }
        .json-container {
            padding: 5px;
            white-space: pre-wrap;
            overflow: auto;
            font-size: 10px;
            font-family: monospace;
            overflow-wrap: anywhere;
        }
        .footer {
            background-color: #f0f0f0;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="pre-header">
            <table>
                <tr>
                    <td style="width: 100%;">
                        <img alt="Embedded Image" height="35px" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABAgAAAC5CAMAAACSnv3rAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAALBUExURQAAAP///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////1gHllsAAADqdFJOUwABAgMEBQYHCAkKCwwOEBITFBUWFxgZGhscHR4gISIkJSYoKSorLC0uLzAxMjQ1Njc4OTo7PD0+P0BBQkNERUZISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4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"/>
                    </td>
                    <td class="date">
                        <div>
                            <table>
                                <tr>
                                    <td>
                                        <div>{{.Time}}</div>
                                    </td>
                                </tr>
                                <tr>
                                    <td>
                                        <div>{{.Date}}</div>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
        <div class="header">
            <h2 class="header-title" style="color: #25ee32">New Event</h2>
            <h1 class="header-title">{{.EventName}}</h1>
        </div>
        <div class="content">
            <h2>An event was triggered, </h2>
            <p>The following JSON represents a complete event document that has been generated by the system. This document includes all the relevant information and details related to the event:
            </p>
            <pre class="json-container">
{{.CloudEvent}}
            </pre>
        </div>
    </div>
</body>
</html>
`

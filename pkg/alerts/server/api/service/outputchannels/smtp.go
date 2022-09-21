package outputchannels

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"text/template"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	"gopkg.in/gomail.v2"
)

type SMTPOutputService struct {
	From              string
	Host              string
	Port              int
	Username          string
	Password          string
	SSL               bool
	Insecure          bool
	EmailTemplateFile string
}

type EmailChannelConfig struct {
	EmailAddress string `json:"email_address"`
}

func (s *SMTPOutputService) ParseEventAndSend(ctx context.Context, eventType string, eventDescription string, eventData map[string]string, channels []api.Channel) error {
	emails := make([]string, 0)
	for _, channel := range channels {
		if channel.Type == api.ChannelTypeEmail {
			configBytes, err := json.Marshal(channel.Config)
			if err != nil {
				continue
			}

			var config EmailChannelConfig
			err = json.Unmarshal(configBytes, &config)
			if err != nil {
				continue
			}

			if config.EmailAddress != "" {
				emails = append(emails, config.EmailAddress)
			}
		}
	}

	emailBody, err := parseTemplate(s.EmailTemplateFile, eventType, eventDescription, eventData)
	if err != nil {
		return err
	}

	if len(emails) > 0 {
		err = s.SendEmail(emails, eventType, emailBody)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SMTPOutputService) SendEmail(to []string, subject string, body string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", s.From)
	msg.SetHeader("To", to...)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", body)
	n := gomail.NewDialer(s.Host, s.Port, s.Username, s.Password)
	if s.Insecure {
		n.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if !s.SSL {
		n.SSL = false
	}

	// Send the email
	if err := n.DialAndSend(msg); err != nil {
		return err
	}
	return nil
}

func parseTemplate(templateFileName string, eventName string, description string, data map[string]string) (string, error) {
	type CloudEventData struct {
		Key   string
		Value string
	}

	cloudEventsData := make([]CloudEventData, 0)
	for k, v := range data {
		cloudEventsData = append(cloudEventsData, CloudEventData{
			Key:   k,
			Value: v,
		})
	}

	templateData := struct {
		EventName   string
		Description string
		Data        []CloudEventData
	}{
		EventName:   eventName,
		Description: description,
		Data:        cloudEventsData,
	}

	t, err := template.ParseFiles(templateFileName)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	if err = t.Execute(buf, templateData); err != nil {
		return "", err
	}

	return buf.String(), nil
}

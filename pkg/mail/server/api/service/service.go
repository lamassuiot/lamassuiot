package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/mail/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/repository"

	"bytes"
	"crypto/tls"
	"html/template"
	"net/smtp"

	gomail "gopkg.in/gomail.v2"
)

var auth smtp.Auth

//Request struct
type MailRequest struct {
	from     string
	to       []string
	subject  string
	body     string
	host     string
	port     int
	username string
	password string
}

type EventFieldsTemplate struct {
	CloudEventFieldName string `json:"event_field_name"`
	EmailFieldName      string `json:"email_field_name"`
}

type EventTemplate struct {
	EventType string                `json:"event_type"`
	Fields    []EventFieldsTemplate `json:"fields"`
}

type Service interface {
	Health(ctx context.Context) bool
	HandleEvent(ctx context.Context, input *api.HandleEventInput) (*api.HandleEventOutput, error)
	SubscribedEvent(ctx context.Context, input *api.SubscribedEventInput) (*api.SubscribedEventOutput, error)
	UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (*api.UnsubscribedEventOutput, error)
	GetEventLogs(ctx context.Context, input *api.GetEventsInput) (*api.GetEventsOutput, error)
	CheckMailConfigiration(ctx context.Context, input *api.CheckMailConfigirationInput) (*api.CheckMailConfigirationOutput, error)
}

type mailService struct {
	logger              log.Logger
	from                string
	smtpAddr            string
	mailRepository      repository.MailConfiguration
	eventsConfiguration map[string]EventTemplate
	mailTemplate        string
}

type SmtpServer struct {
	host string
	port string
}

func (s *SmtpServer) ServerName() string {
	return s.host + ":" + s.port
}

func NewMailService(logger log.Logger, mailRepository repository.MailConfiguration, from string, templateDataFilePath string, mailTemplate string) Service {
	file, _ := ioutil.ReadFile(templateDataFilePath)
	eventsConfigArray := []EventTemplate{}

	eventsConfig := map[string]EventTemplate{}
	for _, v := range eventsConfigArray {
		eventsConfig[v.EventType] = v
	}

	_ = json.Unmarshal(file, &eventsConfig)

	return &mailService{
		logger:              logger,
		mailRepository:      mailRepository,
		eventsConfiguration: eventsConfig,
		mailTemplate:        mailTemplate,
		from:                from,
	}
}

func NewMailRequest(from string, to []string, subject, body string, host string, port int, username string, password string) *MailRequest {
	return &MailRequest{
		from:     from,
		to:       to,
		subject:  subject,
		body:     body,
		host:     host,
		port:     port,
		username: username,
		password: password,
	}
}

func (s *mailService) Health(ctx context.Context) bool {
	return true
}

func (s *mailService) HandleEvent(ctx context.Context, input *api.HandleEventInput) (*api.HandleEventOutput, error) {

	var eventData map[string]string
	jsonBytes := input.Event.Data()
	json.Unmarshal(jsonBytes, &eventData)

	data := map[string]string{}
	if _, ok := s.eventsConfiguration[input.Event.Type()]; !ok {
		for k, v := range eventData {
			data[k] = v
		}
	} else {
		fieldsToUse := s.eventsConfiguration[input.Event.Type()].Fields
		for _, v := range fieldsToUse {
			if _, ok := eventData[v.CloudEventFieldName]; !ok {
				data[v.EmailFieldName] = eventData[v.CloudEventFieldName]
			}
		}
	}

	data["Timestamp"] = input.Event.Time().Format("2006-01-02 3:4:5 pm")

	err := s.mailRepository.InsertAndUpdateEventLog(ctx, input.Event.Type(), input.Event)
	if err != nil {
		return nil, err
	}
	userConfigs, err := s.mailRepository.SelectSubscribersByEventType(ctx, input.Event.Type())
	if err != nil {
		return nil, err
	}

	emails := make([]string, 0)
	for _, v := range userConfigs {
		emails = append(emails, v.Email)

		if err != nil {
			return nil, err
		}
	}
	r := NewMailRequest(s.from, emails, input.Event.Type(), "", "172.16.255.146", 25, "", "")
	err = r.ParseTemplate(s.mailTemplate, parseEventTypeToText(input.Event.Type()), "Some static text", data)
	if err == nil {
		ok, err := r.SendEmail()
		fmt.Println(err)
		fmt.Println(ok)
	}
	return &api.HandleEventOutput{}, nil
}

func (s *mailService) SubscribedEvent(ctx context.Context, input *api.SubscribedEventInput) (*api.SubscribedEventOutput, error) {

	events, err := s.mailRepository.SubscribeToEvents(ctx, input.Email, input.EventType)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.SubscribedEventOutput{}, err
	}

	return &api.SubscribedEventOutput{
		Subscription: events,
	}, nil
}

func (s *mailService) UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (*api.UnsubscribedEventOutput, error) {

	events, err := s.mailRepository.UnSubscribeToEvents(ctx, input.Email, input.EventType)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.UnsubscribedEventOutput{}, err
	}

	return &api.UnsubscribedEventOutput{
		Subscription: events,
	}, nil
}

func (s *mailService) GetEventLogs(ctx context.Context, input *api.GetEventsInput) (*api.GetEventsOutput, error) {

	logEvents, err := s.mailRepository.SelectEventLogs(ctx)
	if err != nil {
		return &api.GetEventsOutput{}, err
	}

	return &api.GetEventsOutput{
		LastEvents: logEvents,
	}, nil
}

func (r *MailRequest) SendEmail() (bool, error) {
	msg := gomail.NewMessage()
	msg.SetHeader("From", r.from)
	msg.SetHeader("To", r.to...)
	msg.SetHeader("Subject", r.subject)
	msg.SetBody("text/html", r.body)

	n := gomail.NewDialer(r.host, r.port, r.username, r.password)
	n.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	n.SSL = false

	// Send the email
	if err := n.DialAndSend(msg); err != nil {
		return false, err
	}
	return true, nil
}

func (s *mailService) CheckMailConfigiration(ctx context.Context, input *api.CheckMailConfigirationInput) (*api.CheckMailConfigirationOutput, error) {

	output := &api.CheckMailConfigirationOutput{
		EmailSent: false,
	}

	// Connect to the SMTP Server
	auth = smtp.PlainAuth("", input.Config.Authentication.Username, input.Config.Authentication.Password, input.Config.Host)

	smtpServer := SmtpServer{host: input.Config.Host, port: input.Config.Port}

	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: input.Config.EnableTLS,
		ServerName:         input.Config.Host,
	}

	// Here is the key, you need to call tls.Dial instead of smtp.Dial
	// for smtp servers running on 465 that require an ssl connection
	// from the very beginning (no starttls)
	var client *smtp.Client
	var err error

	if input.Config.EnableSSL {
		conn, err := tls.Dial("tcp", smtpServer.ServerName(), tlsconfig)
		if err != nil {
			return output, err
		}
		client, err = smtp.NewClient(conn, smtpServer.host)
		if err != nil {
			return output, err
		}
	} else {
		client, err = smtp.Dial(smtpServer.ServerName())
		if err != nil {
			return output, err
		}

	}
	defer client.Close()
	if err = client.Hello(smtpServer.ServerName()); err != nil {
		return output, err
	}

	// Auth
	if input.Config.EnableAuth {

		if err = client.Auth(auth); err != nil {
			return output, err
		}
	}

	// From and To
	if err := validateLine(input.Config.From); err != nil {
		return output, err
	}
	for _, recp := range input.Config.To {
		if err := validateLine(recp); err != nil {
			return output, err
		}
	}
	if err = client.Mail(input.Config.From); err != nil {
		return output, err
	}
	for _, k := range input.Config.To {
		if err = client.Rcpt(k); err != nil {
			return output, err
		}
	}

	// Data
	w, err := client.Data()
	if err != nil {
		return output, err
	}
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	subject := "Subject: " + input.Config.Subject + "!\n"
	msg := []byte(subject + mime + "\n" + input.Config.Body)
	_, err = w.Write(msg)
	if err != nil {
		return output, err
	}

	err = w.Close()
	if err != nil {
		return output, err
	}

	client.Quit()

	return &api.CheckMailConfigirationOutput{
		EmailSent: true,
	}, err

}

func (r *MailRequest) ParseTemplate(templateFileName string, eventName string, description string, data map[string]string) error {
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
		return err
	}
	buf := new(bytes.Buffer)
	if err = t.Execute(buf, templateData); err != nil {
		return err
	}
	r.body = buf.String()
	return nil
}

func parseEventTypeToText(queue string) string {
	array := strings.Split(queue, ".")
	return strings.Join(array[2:], " ")

}

// validateLine checks to see if a line has CR or LF as per RFC 5321
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}

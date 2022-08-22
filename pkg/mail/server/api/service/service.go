package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/mail/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/repository"

	"bytes"
	"html/template"
	"net/smtp"
)

var auth smtp.Auth

//Request struct
type MailRequest struct {
	from    string
	to      []string
	subject string
	body    string
	fromS   string
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
	AddUserConfig(ctx context.Context, input *api.AddUserConfigInput) (*api.AddUserConfigOutput, error)
	SubscribedEvent(ctx context.Context, input *api.SubscribedEventInput) (*api.SubscribedEventOutput, error)
	UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (*api.UnsubscribedEventOutput, error)
}

type mailService struct {
	logger              log.Logger
	from                string
	password            string
	smtpAddr            string
	mailRepository      repository.MailConfiguration
	eventsConfiguration map[string]EventTemplate
	mailTemplate        string
}

func NewMailService(logger log.Logger, from string, password string, smtpAddress string, mailRepository repository.MailConfiguration, templateDataFilePath string, mailTemplate string) Service {
	file, _ := ioutil.ReadFile(templateDataFilePath)
	eventsConfigArray := []EventTemplate{}

	eventsConfig := map[string]EventTemplate{}
	for _, v := range eventsConfigArray {
		eventsConfig[v.EventType] = v
	}

	_ = json.Unmarshal(file, &eventsConfig)

	return &mailService{
		logger:              logger,
		from:                from,
		password:            password,
		smtpAddr:            smtpAddress,
		mailRepository:      mailRepository,
		eventsConfiguration: eventsConfig,
		mailTemplate:        mailTemplate,
	}
}

func NewMailRequest(from string, to []string, subject, body string) *MailRequest {
	return &MailRequest{
		from:    from,
		to:      to,
		subject: subject,
		body:    body,
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

	auth = smtp.PlainAuth("", s.from, s.password, s.smtpAddr)

	userConfigs, err := s.mailRepository.SelectSubscribersByEventType(ctx, input.Event.Type())
	if err != nil {
		return nil, err
	}

	emails := make([]string, 0)
	for _, v := range userConfigs {
		emails = append(emails, v.Email)
	}
	r := NewMailRequest(s.from, emails, input.Event.Type(), "")
	err = r.ParseTemplate(s.mailTemplate, parseEventTypeToText(input.Event.Type()), "Some static text", data)
	if err == nil {
		ok, err := r.SendEmail()
		fmt.Println(err)
		fmt.Println(ok)
	}
	return &api.HandleEventOutput{}, nil
}

func (s *mailService) AddUserConfig(ctx context.Context, input *api.AddUserConfigInput) (*api.AddUserConfigOutput, error) {
	err := s.mailRepository.InsertUserConfiguration(ctx, input.UserID, input.Email, []string{})
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.AddUserConfigOutput{}, err
	}

	userConfig, err := s.mailRepository.SelectUserConfigurationByUserID(ctx, input.UserID)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.AddUserConfigOutput{}, err
	}

	return &api.AddUserConfigOutput{
		UserConfiguration: userConfig,
	}, nil
}

func (s *mailService) SubscribedEvent(ctx context.Context, input *api.SubscribedEventInput) (*api.SubscribedEventOutput, error) {
	var err error

	events, err := s.mailRepository.SubscribeToEvents(ctx, input.UserID, input.EventType)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.SubscribedEventOutput{}, err
	}

	return &api.SubscribedEventOutput{
		UserConfiguration: events,
	}, nil
}

func (s *mailService) UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (*api.UnsubscribedEventOutput, error) {
	var err error

	events, err := s.mailRepository.UnSubscribeToEvents(ctx, input.UserID, input.EventType)
	if err != nil {
		level.Debug(s.logger).Log("err", err)
		return &api.UnsubscribedEventOutput{}, err
	}

	return &api.UnsubscribedEventOutput{
		UserConfiguration: events,
	}, nil
}

func (r *MailRequest) SendEmail() (bool, error) {
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	subject := "Subject: " + r.subject + "!\n"
	msg := []byte(subject + mime + "\n" + r.body)
	addr := "smtp.gmail.com:587"

	if err := smtp.SendMail(addr, auth, r.from, r.to, msg); err != nil {
		return false, err
	}
	return true, nil
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

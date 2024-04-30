package assemblers

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/globalsign/est"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

func TestBindIDEvent(t *testing.T) {
	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, true)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	createCA := func(name string, lifespan string, issuance string) (*models.CACertificate, error) {
		lifespanCABootDur, _ := models.ParseDuration(lifespan)
		issuanceCABootDur, _ := models.ParseDuration(issuance)
		return testServers.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
			Subject:            models.Subject{CommonName: name},
			CAExpiration:       models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&lifespanCABootDur)},
			IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
			Metadata:           map[string]any{},
		})
	}

	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
		input := services.CreateDMSInput{
			ID:       uuid.NewString(),
			Name:     "MyIotFleet",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
					EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
						AuthMode: models.ESTAuthModeClientCertificate,
						AuthOptionsMTLS: models.AuthOptionsClientCertificate{
							ChainLevelValidation: -1,
							ValidationCAs:        []string{},
						},
					},
					DeviceProvisionProfile: models.DeviceProvisionProfile{
						Icon:      "BiSolidCreditCardFront",
						IconColor: "#25ee32-#222222",
						Metadata:  map[string]any{},
						Tags:      []string{"iot", "testdms", "cloud"},
					},
					RegistrationMode:            models.JITP,
					EnableReplaceableEnrollment: true,
				},
				ReEnrollmentSettings: models.ReEnrollmentSettings{
					AdditionalValidationCAs:     []string{},
					ReEnrollmentDelta:           models.TimeDuration(time.Hour),
					EnableExpiredRenewal:        true,
					PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
					CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
				},
				CADistributionSettings: models.CADistributionSettings{
					IncludeLamassuSystemCA: true,
					IncludeEnrollmentCA:    true,
					ManagedCAs:             []string{},
				},
			},
		}

		modifier(&input)

		return dmsMgr.Service.CreateDMS(context.Background(), input)
	}

	evCatcher := func(newMessages <-chan *message.Message, foundChan chan *event.Event) {
		for msg := range newMessages {
			ev, err := eventbus.ParseCloudEvent(msg.Payload)
			if err != nil {
				continue
			}

			if ev.Type() == string(models.EventBindDeviceIdentityKey) {
				foundChan <- ev
			}
		}
	}
	standardEvCheck := func(event event.Event) error {
		if event.Source() != "lrn://dms-manager" {
			return fmt.Errorf("unexpected event source")
		}

		eventData, err := eventbus.GetEventBody[models.BindIdentityToDeviceOutput](&event)
		if err != nil {
			return fmt.Errorf("unexpected event format")
		}

		if eventData == nil {
			return fmt.Errorf("event data is nil")
		}

		if eventData.Certificate == nil {
			return fmt.Errorf("certificate is nil")
		}

		if eventData.DMS == nil {
			return fmt.Errorf("DMS is nil")
		}

		if eventData.Device == nil {
			return fmt.Errorf("device is nil")
		}

		return nil
	}

	var testcases = []struct {
		name            string
		run             func()
		maxTime         time.Duration
		expectToTimeout bool
		eventCatcher    func(newMessages <-chan *message.Message, foundChan chan *event.Event)
		resultCheck     func(event event.Event) error
	}{
		{
			name:            "OK/Enroll",
			expectToTimeout: false,
			run: func() {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

			},
			maxTime:      time.Second * 5,
			eventCatcher: evCatcher,
			resultCheck:  standardEvCheck,
		},
		{
			name:            "OK/ReEnroll",
			expectToTimeout: false,
			run: func() {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				enrollCrt, err := estCli.Enroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				estCli.Certificates = []*x509.Certificate{enrollCrt}
				estCli.PrivateKey = enrollKey

				_, err = estCli.Reenroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while re-enrolling: %s", err)
				}
			},
			maxTime: time.Second * 5,
			eventCatcher: func(newMessages <-chan *message.Message, foundChan chan *event.Event) {
				ctr := 0
				for msg := range newMessages {
					ev, err := eventbus.ParseCloudEvent(msg.Payload)
					if err != nil {
						continue
					}

					if ev.Type() == string(models.EventBindDeviceIdentityKey) {
						ctr++
						if ctr == 2 {
							foundChan <- ev
						}
					}
				}
			},
			resultCheck: standardEvCheck,
		},
		{
			name:            "OK/ManualAssignment",
			expectToTimeout: false,
			run: func() {
				manualEnrollCA, err := createCA("manual-enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					// This function is intentionally left empty as there are no specific settings to be configured for the DMS.
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				deviceKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				deviceCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("device-%s", uuid.NewString())}, deviceKey)
				deviceCert, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         manualEnrollCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(deviceCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				device, err := testServers.DeviceManager.HttpDeviceManagerSDK.CreateDevice(services.CreateDeviceInput{
					ID:        deviceCert.Subject.CommonName,
					Alias:     "",
					Tags:      dms.Settings.EnrollmentSettings.DeviceProvisionProfile.Tags,
					Metadata:  dms.Settings.EnrollmentSettings.DeviceProvisionProfile.Metadata,
					DMSID:     dms.ID,
					Icon:      "my-icon",
					IconColor: "#25ee32",
				})
				if err != nil {
					t.Fatalf("could not register device: %s", err)
				}

				_, err = testServers.DMSManager.HttpDeviceManagerSDK.BindIdentityToDevice(context.Background(), services.BindIdentityToDeviceInput{
					DeviceID:                device.ID,
					CertificateSerialNumber: deviceCert.SerialNumber,
					BindMode:                models.DeviceEventTypeProvisioned,
				})
				if err != nil {
					t.Fatalf("could not updated id slot: %s", err)
				}
			},
			maxTime:      time.Second * 5,
			eventCatcher: evCatcher,
			resultCheck:  standardEvCheck,
		},
		{
			name:            "Err/Enroll",
			expectToTimeout: true,
			run: func() {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				unauthCA, err := createCA("unAuthCA", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         unauthCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				enrollCrt, err := estCli.Enroll(context.Background(), enrollCSR)
				if err == nil {
					t.Fatalf("expected to get an error while enrolling. Got none")
				}

				if enrollCrt != nil {
					t.Fatalf("expected to have a nil certificate. Got a non-nil certificate")
				}
			},
			maxTime: time.Second * 10,
			eventCatcher: func(newMessages <-chan *message.Message, foundChan chan *event.Event) {
				for msg := range newMessages {
					ev, err := eventbus.ParseCloudEvent(msg.Payload)
					if err != nil {
						continue
					}

					if ev.Type() == string(models.EventBindDeviceIdentityKey) {
						foundChan <- ev
					}
				}

			},
			resultCheck: func(event event.Event) error {
				return fmt.Errorf("expected NO event to be analyzed")
			},
		},
		{
			name:            "Err/ReEnroll",
			expectToTimeout: true,
			run: func() {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				enrollCrt, err := estCli.Reenroll(context.Background(), enrollCSR)
				if err == nil {
					t.Fatalf("expected to get an error while re-enrolling. Got none")
				}

				if enrollCrt != nil {
					t.Fatalf("expected to have a nil certificate. Got a non-nil certificate")
				}
			},
			maxTime: time.Second * 10,
			eventCatcher: func(newMessages <-chan *message.Message, foundChan chan *event.Event) {
				ctr := 0
				for msg := range newMessages {
					ev, err := eventbus.ParseCloudEvent(msg.Payload)
					if err != nil {
						continue
					}

					if ev.Type() == string(models.EventBindDeviceIdentityKey) {
						ctr++
						if ctr == 2 {
							foundChan <- ev
						}
					}
				}
			},
			resultCheck: func(event event.Event) error {
				return fmt.Errorf("expected NO event to be analyzed")
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			router, err := eventbus.NewEventBusRouter(
				testServers.EventBus.config,
				uuid.NewString(),
				helpers.ConfigureLogger(config.Info, "Test Case", "router"),
			)
			if err != nil {
				t.Fatalf("could not instantiate a messaging router: %s", err)
			}

			subscriber, err := eventbus.NewEventBusSubscriber(
				testServers.EventBus.config,
				uuid.NewString(),
				helpers.ConfigureLogger(config.Trace, "Test Case", "sub"),
			)
			if err != nil {
				t.Fatalf("could not subscribe: %s", err)
			}

			resultChannel := make(chan *event.Event, 1)
			newMessages := make(chan *message.Message)

			defer close(resultChannel)
			defer close(newMessages)

			router.AddNoPublisherHandler(tc.name, "#", subscriber, func(msg *message.Message) error {
				newMessages <- msg
				return nil
			})

			go tc.eventCatcher(newMessages, resultChannel)

			ctxTimeout, cancel := context.WithTimeout(context.Background(), tc.maxTime)
			defer cancel()
			go router.Run(context.Background())

			tc.run()

			select {
			case <-ctxTimeout.Done():
				if !tc.expectToTimeout {
					t.Fatalf("did not receive a valid event within %f seconds", tc.maxTime.Seconds())
				}
			case ev := <-resultChannel:
				if tc.expectToTimeout {
					t.Fatalf("expected timeout. Got event to be analyzed")
				}
				err = tc.resultCheck(*ev)
				if err != nil {
					t.Fatalf("invalid event: %s", err)
				}
			}
		})
	}
}

package assemblers

// import (
// 	"context"
// 	"crypto/elliptic"
// 	"crypto/x509"
// 	"fmt"
// 	"testing"
// 	"time"

// 	"github.com/ThreeDotsLabs/watermill/message"
// 	"github.com/cloudevents/sdk-go/v2/event"
// 	"github.com/globalsign/est"
// 	"github.com/google/uuid"
// 	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
// 	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
// 	"github.com/lamassuiot/lamassuiot/v2/pkg/messaging"
// 	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
// 	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
// )

// func TestBindIDEvent(t *testing.T) {
// 	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, true)
// 	if err != nil {
// 		t.Fatalf("could not create DMS Manager test server: %s", err)
// 	}

// 	createCA := func(name string, lifespan string, issuance string) (*models.CACertificate, error) {
// 		lifespanCABootDur, _ := models.ParseDuration(lifespan)
// 		issuanceCABootDur, _ := models.ParseDuration(issuance)
// 		return testServers.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
// 			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
// 			Subject:            models.Subject{CommonName: name},
// 			CAExpiration:       models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&lifespanCABootDur)},
// 			IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
// 			Metadata:           map[string]any{},
// 		})
// 	}

// 	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
// 		input := services.CreateDMSInput{
// 			ID:       uuid.NewString(),
// 			Name:     "MyIotFleet",
// 			Metadata: map[string]any{},
// 			Settings: models.DMSSettings{
// 				EnrollmentSettings: models.EnrollmentSettings{
// 					EnrollmentProtocol: models.EST,
// 					EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
// 						AuthMode: models.ESTAuthModeClientCertificate,
// 						AuthOptionsMTLS: models.AuthOptionsClientCertificate{
// 							ChainLevelValidation: -1,
// 							ValidationCAs:        []string{},
// 						},
// 					},
// 					DeviceProvisionProfile: models.DeviceProvisionProfile{
// 						Icon:      "BiSolidCreditCardFront",
// 						IconColor: "#25ee32-#222222",
// 						Metadata:  map[string]any{},
// 						Tags:      []string{"iot", "testdms", "cloud"},
// 					},
// 					RegistrationMode:            models.JITP,
// 					EnableReplaceableEnrollment: true,
// 				},
// 				ReEnrollmentSettings: models.ReEnrollmentSettings{
// 					AdditionalValidationCAs:     []string{},
// 					ReEnrollmentDelta:           models.TimeDuration(time.Hour),
// 					EnableExpiredRenewal:        true,
// 					PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
// 					CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
// 				},
// 				CADistributionSettings: models.CADistributionSettings{
// 					IncludeLamassuSystemCA: true,
// 					IncludeEnrollmentCA:    true,
// 					ManagedCAs:             []string{},
// 				},
// 			},
// 		}

// 		modifier(&input)

// 		return dmsMgr.Service.CreateDMS(context.Background(), input)
// 	}

// 	var testcases = []struct {
// 		name        string
// 		run         func()
// 		resultCheck func(event event.Event) error
// 	}{
// 		{
// 			name: "OK/Enroll",
// 			run: func() {
// 				bootstrapCA, err := createCA("boot", "1y", "1m")
// 				if err != nil {
// 					t.Fatalf("could not create bootstrap CA: %s", err)
// 				}

// 				enrollCA, err := createCA("enroll", "1y", "1m")
// 				if err != nil {
// 					t.Fatalf("could not create Enrollment CA: %s", err)
// 				}

// 				dms, err := createDMS(func(in *services.CreateDMSInput) {
// 					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
// 					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
// 						bootstrapCA.ID,
// 					}
// 				})
// 				if err != nil {
// 					t.Fatalf("could not create DMS: %s", err)
// 				}

// 				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
// 				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
// 				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
// 					CAID:         bootstrapCA.ID,
// 					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
// 					SignVerbatim: true,
// 				})
// 				if err != nil {
// 					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
// 				}

// 				estCli := est.Client{
// 					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
// 					AdditionalPathSegment: dms.ID,
// 					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
// 					PrivateKey:            bootKey,
// 					InsecureSkipVerify:    true,
// 				}

// 				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
// 				enrollKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
// 				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

// 				_, err = estCli.Enroll(context.Background(), enrollCSR)
// 				if err != nil {
// 					t.Fatalf("unexpected error while enrolling: %s", err)
// 				}

// 				fmt.Println("Enrolledddd")
// 			},
// 		},
// 	}

// 	for _, tc := range testcases {
// 		tc := tc

// 		t.Run(tc.name, func(t *testing.T) {
// 			messageEngine, err := messaging.NewMessagingEngine(helpers.ConfigureLogger(config.Info, "eventbus"), testServers.EventBus.config, uuid.NewString())
// 			if err != nil {
// 				t.Fatalf("could not instantiate a messaging engine: %s", err)
// 			}

// 			go messaging.SubscribeAndHandle(messageEngine, string(models.EventBindDeviceIdentityKey), func(msg *message.Message) {
// 				fmt.Println(msg.Payload)
// 			})
// 			if err != nil {
// 				t.Fatalf("could not subscribe: %s", err)
// 			}

// 			tc.run()
// 		})
// 	}
// }

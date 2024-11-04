package eventbus

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/async-messaging/rabbitmq"
	awsplatform_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/aws-platform"
)

var sqsTestServer *TestEventBusConfig
var rabbitTestServer *TestEventBusConfig

type TestEventBusConfig struct {
	config     config.EventBusEngine
	BeforeEach func() error
	AfterSuite func()
}

func prepareAWSSqsSNSForTest() (*TestEventBusConfig, error) {
	if sqsTestServer != nil {
		return sqsTestServer, nil
	}

	cleanup, conf, err := awsplatform_test.RunAWSEmulationLocalStackDocker()
	if err != nil {
		return nil, err
	}

	sqsTestServer = &TestEventBusConfig{
		config: config.EventBusEngine{
			LogLevel:  cconfig.Debug,
			Enabled:   true,
			Provider:  config.AWSSqsSns,
			AWSSqsSns: *conf,
		},
		AfterSuite: func() { cleanup() },
		BeforeEach: func() error {
			return nil
		},
	}

	return sqsTestServer, nil
}

func prepareRabbitMQForTest() (*TestEventBusConfig, error) {

	if rabbitTestServer != nil {
		return rabbitTestServer, nil
	}

	cleanup, conf, _, err := rabbitmq_test.RunRabbitMQDocker()
	if err != nil {
		return nil, err
	}

	rabbitTestServer = &TestEventBusConfig{
		config: config.EventBusEngine{
			LogLevel: cconfig.Debug,
			Enabled:  true,
			Provider: config.Amqp,
			Amqp:     *conf,
		},
		AfterSuite: func() { cleanup() },
		BeforeEach: func() error {
			return nil
		},
	}

	return rabbitTestServer, nil
}

func setupSuite() func(t *testing.T) {
	aws, err := prepareAWSSqsSNSForTest()
	if err != nil {
		return nil
	}
	sns, err := prepareRabbitMQForTest()

	if err != nil {
		return nil
	}

	return func(t *testing.T) {
		aws.AfterSuite()
		sns.AfterSuite()
	}
}

type basicTestHandler struct {
	handler func(*message.Message) error
}

func (h *basicTestHandler) HandleMessage(msg *message.Message) error {
	return h.handler(msg)
}

func TestSuiteEventBus(t *testing.T) {
	teardown := setupSuite()
	defer teardown(t)

	t.Run("TestWildcardSubscribe", testWildcardSubscribe)
	t.Run("TestMultiServiceSubscribe", testMultiServiceSubscribe)
	t.Run("TestMultiConsumers", testMultiConsumers)
}

func testWildcardSubscribe(t *testing.T) {
	testcases := []struct {
		name            string
		subscriptionKey string
		expectedTimeout bool
	}{
		{
			name:            "OK/NoWildcard",
			subscriptionKey: "my.topic.test",
			expectedTimeout: false,
		},
		{
			name:            "OK/WildcardAtEnd",
			subscriptionKey: "my.topic.#",
			expectedTimeout: false,
		},
		{
			name:            "Err/Timeout",
			subscriptionKey: "another.topic",
			expectedTimeout: true,
		},
	}

	eventBusEngines := []struct {
		name string
		conf *TestEventBusConfig
	}{
		{
			name: "RabbitMQ",
			conf: rabbitTestServer,
		},
		{
			name: "AWSSqsSNS",
			conf: sqsTestServer,
		},
	}

	for _, eventBusConf := range eventBusEngines {
		pub, err := NewEventBusPublisher(eventBusConf.conf.config, "test-pub", helpers.SetupLogger(cconfig.Debug, "Test Case", "pub"))
		if err != nil {
			t.Fatalf("could not create publisher: %s", err)
		}

		for _, tc := range testcases {
			tc := tc

			t.Run(fmt.Sprintf("%s-%s", eventBusConf.name, tc.name), func(t *testing.T) {
				subAndPub := func(publishFunc func() error) error {
					logger := helpers.SetupLogger(cconfig.Debug, "Test Case", "sub")

					resultChannel := make(chan int, 1)

					subHandler, err := NewEventBusSubscriptionHandler(eventBusConf.conf.config, fmt.Sprintf("test-sub-%d", time.Now().UnixMilli()), logger, &basicTestHandler{
						handler: func(msg *message.Message) error {
							resultChannel <- 1
							return nil
						},
					}, "test-handler", tc.subscriptionKey)
					if err != nil {
						return fmt.Errorf("could not create subscription handler: %s", err)
					}

					err = subHandler.RunAsync()
					if err != nil {
						return fmt.Errorf("could not run subscription handler: %s", err)
					}

					time.Sleep(3 * time.Second)
					err = publishFunc()

					ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					if err != nil {
						return fmt.Errorf("could not publish message: %s", err)
					}

					select {
					case <-ctxTimeout.Done():
						subHandler.Stop()
						if !tc.expectedTimeout {
							return fmt.Errorf("did not receive a valid event within 5 seconds")
						} else {
							return nil
						}
					case <-resultChannel:
						subHandler.Stop()
						if tc.expectedTimeout {
							return fmt.Errorf("received an event when it was not expected")
						} else {
							return nil
						}
					}
				}

				err := subAndPub(func() error {
					return pub.Publish("my.topic.test", message.NewMessage(uuid.NewString(), []byte("test msg")))
				})
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
			})
		}
	}
}

func testMultiServiceSubscribe(t *testing.T) {
	type sub struct {
		serviceID       string
		subscriptionKey string
		shouldTimeout   bool
	}

	testcases := []struct {
		name          string
		subscriptions []sub
	}{
		{
			name: "OK/3Subs",
			subscriptions: []sub{
				{
					serviceID:       "service-1",
					subscriptionKey: "my.topic.test",
					shouldTimeout:   false,
				},
				{
					serviceID:       "service-2",
					subscriptionKey: "my.topic.test",
					shouldTimeout:   false,
				},
				{
					serviceID:       "service-3",
					subscriptionKey: "my.topic.test",
					shouldTimeout:   false,
				},
			},
		},
		{
			name: "OK/2OKSubs1NOK",
			subscriptions: []sub{
				{
					serviceID:       "service-1",
					subscriptionKey: "my.topic.test",
					shouldTimeout:   false,
				},
				{
					serviceID:       "service-2",
					subscriptionKey: "my.topic.test",
					shouldTimeout:   false,
				},
				{
					serviceID:       "service-3",
					subscriptionKey: "another.topic",
					shouldTimeout:   true,
				},
			},
		},
	}

	eventBusEngines := []struct {
		name string
		conf *TestEventBusConfig
	}{
		{
			name: "RabbitMQ",
			conf: rabbitTestServer,
		},
		{
			name: "AWSSqsSNS",
			conf: sqsTestServer,
		},
	}

	for _, eventBusConf := range eventBusEngines {
		pub, err := NewEventBusPublisher(eventBusConf.conf.config, "test-pub", helpers.SetupLogger(cconfig.Debug, "Test Case", "pub"))
		if err != nil {
			t.Fatalf("could not create publisher: %s", err)
		}

		for _, tc := range testcases {
			tc := tc

			t.Run(fmt.Sprintf("%s-%s", eventBusConf.name, tc.name), func(t *testing.T) {
				subAndPub := func(publishFunc func() error) error {
					logger := helpers.SetupLogger(cconfig.Debug, "Test Case", "sub")

					resultChannel := make(chan string)

					stopAllFuncs := []func(){}
					responses := []string{}

					for _, sub := range tc.subscriptions {
						subHandler, err := NewEventBusSubscriptionHandler(eventBusConf.conf.config, fmt.Sprintf("%s-%s-%d", strings.ReplaceAll(tc.name, "/", "-"), sub.serviceID, time.Now().UnixMilli()), logger, &basicTestHandler{
							handler: func(msg *message.Message) error {
								t.Logf("subscriber %s - %s message ACK", sub.serviceID, sub.subscriptionKey)
								resultChannel <- sub.serviceID
								return nil
							},
						}, fmt.Sprintf("test-handler-%s-%d", sub.serviceID, time.Now().UnixMilli()), sub.subscriptionKey)
						if err != nil {
							return fmt.Errorf("could not create subscription handler: %s", err)
						}

						stopAllFuncs = append(stopAllFuncs, subHandler.Stop)
						err = subHandler.RunAsync()
						if err != nil {
							return fmt.Errorf("could not run subscription handler: %s", err)
						}

						fmt.Println("ready")
					}

					stopAll := func() {
						for _, stopFunc := range stopAllFuncs {
							stopFunc()
						}
					}

					time.Sleep(3 * time.Second)

					ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					err = publishFunc()
					if err != nil {
						return fmt.Errorf("could not publish message: %s", err)
					}

					for {
						shouldBreak := false
						select {
						case <-ctxTimeout.Done():
							shouldBreak = true
						case serviceID := <-resultChannel:
							// Update result and check if we should stop
							t.Logf("result received: %s", serviceID)

							responses = append(responses, serviceID)
							if len(responses) == len(tc.subscriptions) {
								//all responses received
								shouldBreak = true
							}
						}

						if shouldBreak {
							break
						}
					}

					stopAll()

					for _, sub := range tc.subscriptions {
						if sub.shouldTimeout && slices.Contains(responses, sub.serviceID) {
							t.Logf("error: subscriber %s - %s should have timed out, but it did not", sub.serviceID, sub.subscriptionKey)
							return fmt.Errorf("received a message when it was not expected")
						} else if !sub.shouldTimeout && !slices.Contains(responses, sub.serviceID) {
							t.Logf("error: subscriber %s - %s should have received a message, but it did not", sub.serviceID, sub.subscriptionKey)
							return fmt.Errorf("did not receive a message when it was expected")
						} else {
							t.Logf("subscriber %s - %s received message", sub.serviceID, sub.subscriptionKey)
						}
					}

					return nil
				}

				err := subAndPub(func() error {
					return pub.Publish("my.topic.test", message.NewMessage(uuid.NewString(), []byte("test msg")))
				})
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
			})
		}
	}
}

func testMultiConsumers(t *testing.T) {
	type sub struct {
		consumerID      string
		serviceID       string
		subscriptionKey string
	}

	eventBusEngines := []struct {
		name string
		conf *TestEventBusConfig
	}{
		{
			name: "RabbitMQ",
			conf: rabbitTestServer,
		},
		{
			name: "AWSSqsSNS",
			conf: sqsTestServer,
		},
	}

	testcases := []struct {
		name           string
		subscriptions  []sub
		expectedResult map[string]int
	}{
		{
			name: "OK/3Consumers",
			subscriptions: []sub{
				{
					consumerID:      "1",
					serviceID:       "service-1",
					subscriptionKey: "my.topic.test",
				},
				{
					consumerID:      "2",
					serviceID:       "service-1",
					subscriptionKey: "my.topic.test",
				},
				{
					consumerID:      "3",
					serviceID:       "service-2",
					subscriptionKey: "my.topic.test",
				},
			},
			expectedResult: map[string]int{
				"service-1": 1,
				"service-2": 1,
			},
		},
	}

	for _, eventBusConf := range eventBusEngines {
		pub, err := NewEventBusPublisher(eventBusConf.conf.config, "test-pub", helpers.SetupLogger(cconfig.Debug, "Test Case", "pub"))
		if err != nil {
			t.Fatalf("could not create publisher: %s", err)
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(fmt.Sprintf("%s-%s", eventBusConf.name, tc.name), func(t *testing.T) {
				subAndPub := func(publishFunc func() error) error {
					logger := helpers.SetupLogger(cconfig.Debug, "Test Case", "sub")

					resultChannel := make(chan string)

					stopAllFuncs := []func(){}
					responses := map[string]int{}

					for _, sub := range tc.subscriptions {
						//SQS Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length
						subHandler, err := NewEventBusSubscriptionHandler(eventBusConf.conf.config, fmt.Sprintf("%s-%s", strings.ReplaceAll(tc.name, "/", "-"), sub.serviceID), logger, &basicTestHandler{
							handler: func(msg *message.Message) error {
								t.Logf("subscriber %s - %s message ACK", sub.serviceID, sub.subscriptionKey)
								resultChannel <- sub.serviceID
								return nil
							},
						}, fmt.Sprintf("test-handler-%s-%s-%d", sub.serviceID, sub.consumerID, time.Now().UnixMilli()), sub.subscriptionKey)
						if err != nil {
							return fmt.Errorf("could not create subscription handler: %s", err)
						}

						stopAllFuncs = append(stopAllFuncs, subHandler.Stop)

						err = subHandler.RunAsync()
						if err != nil {
							return fmt.Errorf("could not run subscription handler: %s", err)
						}
					}

					stopAll := func() {
						for _, stopFunc := range stopAllFuncs {
							stopFunc()
						}
					}

					time.Sleep(3 * time.Second)

					ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					err = publishFunc()
					if err != nil {
						return fmt.Errorf("could not publish message: %s", err)
					}

					for {
						shouldBreak := false
						select {
						case <-ctxTimeout.Done():
							shouldBreak = true
						case serviceID := <-resultChannel:
							// Update result and check if we should stop
							t.Logf("result received: %s", serviceID)

							if _, ok := responses[serviceID]; !ok {
								responses[serviceID] = 1
							} else {
								responses[serviceID]++
							}
						}

						if shouldBreak {
							break
						}
					}

					stopAll()

					for _, sub := range tc.subscriptions {
						if tc.expectedResult[sub.serviceID] != responses[sub.serviceID] {
							t.Logf("error: subscriber %s - %s should have received %d messages, but it received %d", sub.serviceID, sub.subscriptionKey, tc.expectedResult[sub.serviceID], responses[sub.serviceID])
							return fmt.Errorf("did not receive the expected number of messages")
						} else {
							t.Logf("subscriber %s - %s received %d messages", sub.serviceID, sub.subscriptionKey, responses[sub.serviceID])
						}
					}

					return nil
				}

				err := subAndPub(func() error {
					return pub.Publish("my.topic.test", message.NewMessage(uuid.NewString(), []byte("test msg")))
				})
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
			})
		}
	}
}

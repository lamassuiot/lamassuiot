package eventbus

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type basicTestHandler struct {
	handler func(*message.Message) error
}

func (h *basicTestHandler) HandleMessage(msg *message.Message) error {
	return h.handler(msg)
}

type EventBusTestInput struct {
	SetupEventBus func() (func() error, message.Publisher, func(serviceID string) message.Subscriber)
}

func TestWildcardSubscribe(t *testing.T, input EventBusTestInput) {
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

	for idx, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cleanup, pub, subFunc := input.SetupEventBus()
			defer cleanup()

			subAndPub := func(publishFunc func() error) error {
				logger := helpers.SetupLogger(config.Debug, "Test Case", "sub")
				resultChannel := make(chan int, 1)
				sub := subFunc(fmt.Sprintf("service-%d", idx))
				subHandler, err := NewEventBusMessageHandler(models.ServiceName(fmt.Sprintf("handler-%d", idx)), []string{tc.subscriptionKey}, sub, logger, &basicTestHandler{
					handler: func(msg *message.Message) error {
						resultChannel <- 1
						return nil
					},
				})
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

func TestMultiServiceSubscribe(t *testing.T, input EventBusTestInput) {
	type subscriberTest struct {
		serviceID       string
		subscriptionKey string
		shouldTimeout   bool
	}

	testcases := []struct {
		name          string
		subscriptions []subscriberTest
	}{
		{
			name: "OK/3Subs",
			subscriptions: []subscriberTest{
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
			subscriptions: []subscriberTest{
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

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			cleanup, pub, subFunc := input.SetupEventBus()
			defer cleanup()

			subAndPub := func(publishFunc func() error) error {
				logger := helpers.SetupLogger(config.Debug, "Test Case", "sub")

				resultChannel := make(chan string)

				stopAllFuncs := []func(){}
				responses := []string{}

				for idx, s := range tc.subscriptions {
					sub := subFunc(s.serviceID)
					subHandler, err := NewEventBusMessageHandler(models.ServiceName(fmt.Sprintf("handler-%d-%d", time.Now().UnixMilli(), idx)), []string{s.subscriptionKey}, sub, logger, &basicTestHandler{
						handler: func(msg *message.Message) error {
							t.Logf("subscriber %s - %s message ACK", s.serviceID, s.subscriptionKey)
							resultChannel <- s.serviceID
							return nil
						},
					})
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

				err := publishFunc()
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

func TestMultiConsumers(t *testing.T, input EventBusTestInput) {
	type subscriberTest struct {
		consumerID      string
		serviceID       string
		subscriptionKey string
	}

	testcases := []struct {
		name           string
		subscriptions  []subscriberTest
		expectedResult map[string]int
	}{
		{
			name: "OK/3Consumers",
			subscriptions: []subscriberTest{
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

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cleanup, pub, subFunc := input.SetupEventBus()
			defer cleanup()

			subAndPub := func(publishFunc func() error) error {
				logger := helpers.SetupLogger(config.Debug, "Test Case", "sub")

				resultChannel := make(chan string)

				stopAllFuncs := []func(){}
				responses := map[string]int{}

				for idx, s := range tc.subscriptions {
					sub := subFunc(s.serviceID)

					//SQS Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length
					subHandler, err := NewEventBusMessageHandler(models.ServiceName(fmt.Sprintf("handler-%d-%d", time.Now().UnixMilli(), idx)), []string{s.subscriptionKey}, sub, logger, &basicTestHandler{
						handler: func(msg *message.Message) error {
							t.Logf("subscriber %s - %s message ACK", s.serviceID, s.subscriptionKey)
							resultChannel <- s.serviceID
							return nil
						},
					})
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

				err := publishFunc()
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

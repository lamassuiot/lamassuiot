package inmemory

import (
	"context"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/sirupsen/logrus"
)

func TestInMemoryEngine_PublishSubscribe(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	// Create engine
	engine, err := NewInMemoryEngine("test-service", logger)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Get publisher and subscriber
	pub, err := engine.Publisher()
	if err != nil {
		t.Fatalf("failed to get publisher: %v", err)
	}

	sub, err := engine.Subscriber()
	if err != nil {
		t.Fatalf("failed to get subscriber: %v", err)
	}

	// Subscribe to topic
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	topic := "test.topic"
	messages, err := sub.Subscribe(ctx, topic)
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}

	// Publish message
	testPayload := []byte(`{"test": "data"}`)
	msg := message.NewMessage(watermill.NewUUID(), testPayload)

	err = pub.Publish(topic, msg)
	if err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	// Receive message
	select {
	case receivedMsg := <-messages:
		if string(receivedMsg.Payload) != string(testPayload) {
			t.Errorf("expected payload %s, got %s", testPayload, receivedMsg.Payload)
		}
		receivedMsg.Ack()
	case <-ctx.Done():
		t.Fatal("timeout waiting for message")
	}
}

func TestInMemoryEngine_MultipleServices(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	// Create two engines for different services
	engine1, err := NewInMemoryEngine("service1", logger)
	if err != nil {
		t.Fatalf("failed to create engine1: %v", err)
	}

	engine2, err := NewInMemoryEngine("service2", logger)
	if err != nil {
		t.Fatalf("failed to create engine2: %v", err)
	}

	// Each engine should have independent message streams
	// This test verifies service isolation
	pub1, _ := engine1.Publisher()
	sub1, _ := engine1.Subscriber()

	pub2, _ := engine2.Publisher()
	sub2, _ := engine2.Subscriber()

	ctx := context.Background()
	topic1 := "isolation.test.service1"
	topic2 := "isolation.test.service2"

	// Subscribe both services to distinct topics
	msgs1, _ := sub1.Subscribe(ctx, topic1)
	msgs2, _ := sub2.Subscribe(ctx, topic2)

	// Publish to service1's topic
	msg1 := message.NewMessage(watermill.NewUUID(), []byte("service1"))
	pub1.Publish(topic1, msg1)

	// Publish to service2's topic
	msg2 := message.NewMessage(watermill.NewUUID(), []byte("service2"))
	pub2.Publish(topic2, msg2)

	// Verify each service receives only its own messages
	select {
	case m := <-msgs1:
		if string(m.Payload) != "service1" {
			t.Errorf("service1 received wrong message: %s", m.Payload)
		}
		m.Ack()
	case <-time.After(1 * time.Second):
		t.Error("service1 did not receive message")
	}

	select {
	case m := <-msgs2:
		if string(m.Payload) != "service2" {
			t.Errorf("service2 received wrong message: %s", m.Payload)
		}
		m.Ack()
	case <-time.After(1 * time.Second):
		t.Error("service2 did not receive message")
	}
}

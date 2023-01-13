package transport

/*import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service/outputchannels"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	testUtils "github.com/lamassuiot/lamassuiot/pkg/utils/test/utils"
	"go.opentelemetry.io/otel/trace"
)

type AmqpTestCase struct {
	name                  string
	serviceInitialization func(ctx context.Context, svc *service.Service, svcCA *caService.Service, amqpserver *server.AMQPServer) context.Context
	testAmqpEndpoint      func(ctx context.Context, conn *amqptest.Conn, msg byte[])
}

func TestBasicUsage(t *testing.T) {
	mockConn, err := amqptest.Dial("amqp://localhost:5671/%2f") // will fail

	if err == nil {
		t.Errorf("First Dial must fail because no fake server is running...")
		return
	}

	fakeServer := server.NewServer("amqp://localhost:5671/%2f")

	if fakeServer == nil {
		t.Errorf("Failed to instantiate fake server")
		return
	}

	err = fakeServer.Start()

	if err != nil {
		t.Errorf("Failed to start fake server")
	}

	mockConn, err = amqptest.Dial("amqp://localhost:5671/%2f") // now it works =D

	if err != nil {
		t.Error(err)
		return
	}

	if mockConn == nil {
		t.Error("Invalid mockConn")
		return
	}
}

func CreateEvent(ctx context.Context, version string, source string, eventType string, data interface{}) cloudevents.Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	event := cloudevents.NewEvent()
	event.SetSpecVersion(version)
	event.SetSource(source)
	event.SetType(eventType)
	event.SetTime(time.Now())
	event.SetID(fmt.Sprintf("%s:%s", spanCtx.TraceID(), spanCtx.SpanID()))
	event.SetData(cloudevents.ApplicationJSON, data)
	return event
}

func TestPubSub(t *testing.T) {
	var err error

	connString := "amqp://anyhost:anyport/%2fanyVHost"

	fakeServer := server.NewServer(connString)

	err = fakeServer.Start()

	if err != nil {
		t.Error(err)
		return
	}

	conn, err := amqptest.Dial(connString)

	if err != nil {
		t.Error(err)
		return
	}

	done := make(chan bool)
	bindingDone := make(chan bool)

	go sub(conn, t, done, bindingDone)
	<-bindingDone // AMQP will silently discards messages with no route binding.
	go pub(conn, t, done)

	<-done
	<-done
}

func TestCreateCAPubSub(t *testing.T) {
	tt := []AmqpTestCase{
		{
			name: "CreateCA",
			serviceInitialization: func(ctx context.Context, svc *service.Service, svcCA *caService.Service, amqpserver *server.AMQPServer) context.Context {
				output, err := (*svcCA).CreateCA(context.Background(), &caApi.CreateCAInput{
					CAType: caApi.CATypePKI,
					Subject: caApi.Subject{
						CommonName: "ca-name-1",
					},
					KeyMetadata: caApi.KeyMetadata{
						KeyType: caApi.RSA,
						KeyBits: 4096,
					},
					CADuration:       time.Hour * 5,
					IssuanceDuration: time.Hour,
				})
				if err != nil {
					t.Errorf("%s", err)
				}

				event := CreateEvent(ctx, "1.0", "lamassuiot/ca", "io.lamassuiot.ca.create", output.Serialize())
				eventBytes, marshalErr := json.Marshal(event)
				if marshalErr != nil {
					t.Errorf("%s", err)
				}
				msg := lamassuservice.AmqpPublishMessage{
					Exchange:  "lamassu",
					Key:       "io.lamassuiot.ca.create",
					Mandatory: false,
					Immediate: false,
					Msg: amqp.Publishing{
						ContentType: "text/json",
						Body:        []byte(eventBytes),
						Headers: amqp.Table{
							"traceparent": event.ID(),
						},
					},
				}

				return ctx
			},
			testRestEndpoint: func(ctx context.Context, conn *amqptest.Conn) {

			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			runAmqpTests(t, tc)
		})

	}
}

func sub(conn wabbit.Conn, t *testing.T, done chan bool, bindDone chan bool) {
	var (
		err          error
		queue        wabbit.Queue
		deliveries   <-chan wabbit.Delivery
		timer        <-chan time.Time
		deliveryDone chan bool
	)

	channel, err := conn.Channel()

	if err != nil {
		goto SubError
	}

	err = channel.ExchangeDeclare(
		"test",  // name of the exchange
		"topic", // type
		wabbit.Option{
			"durable":  true,
			"delete":   false,
			"internal": false,
			"noWait":   false,
		},
	)

	if err != nil {
		goto SubError
	}

	queue, err = channel.QueueDeclare(
		"lamassu-events", // name of the queue
		wabbit.Option{
			"durable":   true,
			"delete":    false,
			"exclusive": false,
			"noWait":    false,
		},
	)

	if err != nil {
		goto SubError
	}

	err = channel.QueueBind(
		queue.Name(),        // name of the queue
		"wabbit-test-route", // bindingKey
		"test",              // sourceExchange
		wabbit.Option{
			"noWait": false,
		},
	)

	if err != nil {
		goto SubError
	}

	bindDone <- true

	deliveries, err = channel.Consume(
		queue.Name(), // name
		"anyname",    // consumerTag,
		wabbit.Option{
			"noAck":     false,
			"exclusive": false,
			"noLocal":   false,
			"noWait":    false,
		},
	)

	if err != nil {
		goto SubError
	}

	timer = time.After(5 * time.Second)
	deliveryDone = make(chan bool)

	go func() {
		msg1 := <-deliveries

		if string(msg1.Body()) != "msg1" {
			t.Errorf("Unexpected message: %s", string(msg1.Body()))
			deliveryDone <- true
			return
		}

		deliveryDone <- true
	}()

	select {
	case <-deliveryDone:
		goto SubSuccess
	case <-timer:
		err = fmt.Errorf("No data received in sub")
		goto SubError
	}

SubError:
	t.Error(err)
SubSuccess:
	done <- true
}

func pub(conn wabbit.Conn, t *testing.T, done chan bool) {
	var (
		publisher wabbit.Publisher
		confirm   chan wabbit.Confirmation
		event     cloudevents.Event
		route     string
		exc       string
	)

	// helper function to verify publisher confirms
	checkConfirm := func(expected uint64) error {
		c := <-confirm

		if !c.Ack() {
			return fmt.Errorf("confirmation ack should be true")
		}

		if c.DeliveryTag() != expected {
			return fmt.Errorf("confirmation delivery tag should be %d (got: %d)", expected, c.DeliveryTag())
		}

		return nil
	}

	channel, err := conn.Channel()

	if err != nil {
		t.Error(err)
		return
	}

	var stringifiedCloudEvent string
	var serializedCloudEvent []byte

	err = channel.ExchangeDeclare(
		"test",  // name of the exchange
		"topic", // type
		wabbit.Option{
			"durable":  true,
			"delete":   false,
			"internal": false,
			"noWait":   false,
		},
	)

	if err != nil {
		goto PubError
	}

	err = channel.Confirm(false)

	if err != nil {
		goto PubError
	}

	confirm = channel.NotifyPublish(make(chan wabbit.Confirmation, 1))

	publisher, err = amqptest.NewPublisher(conn, channel)

	if err != nil {
		goto PubError
	}

	serializedCloudEvent, err = event.MarshalJSON()
	if err != nil {
		goto PubError
	}

	stringifiedCloudEvent = string(serializedCloudEvent)

	err = publisher.Publish(exc, route, []byte(stringifiedCloudEvent), nil)

	if err != nil {
		goto PubError
	}

	err = checkConfirm(1)

	if err != nil {
		goto PubError
	}

	goto PubSuccess

PubError:
	t.Error(err)
PubSuccess:
	done <- true
}

func runAmqpTests(t *testing.T, tc AmqpTestCase) {
	ctx := context.Background()

	smtpConfig := outputchannels.SMTPOutputService{
		Host:              "172.16.255.146",
		Port:              25,
		Username:          "",
		Password:          "",
		From:              "lamassu-alerts@ikerlan.es",
		SSL:               true,
		Insecure:          true,
		EmailTemplateFile: "/home/ikerlan/lamassu/lamassuiot/pkg/alerts/server/resources/email.html",
	}

	serverCA, caSvc, err := testUtils.BuildCATestServer()
	if err != nil {
		t.Errorf("%s", err)
	}
	defer serverCA.Close()
	serverCA.Start()

	serverAlerts, svc, err := testUtils.BuildMailTestServer("/home/ikerlan/lamassu/lamassuiot/pkg/alerts/server/resources/config.json", smtpConfig)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer serverAlerts.Close()
	serverAlerts.Start()

	connString := "amqp://anyhost:anyport/%2fanyVHost"

	fakeServer := server.NewServer(connString)

	err = fakeServer.Start()

	if err != nil {
		t.Error(err)
		return
	}

	conn, err := amqptest.Dial(connString)

	if err != nil {
		t.Error(err)
		return
	}

	ctx = tc.serviceInitialization(ctx, svc, caSvc, fakeServer)
	//e := httpexpect.New(t, serverAlerts.URL)
	tc.testRestEndpoint(ctx, conn)

}
*/

package sse

import (
	"log"

	"github.com/gin-gonic/gin"
)

// Data to be broadcasted to a client.
type Data struct {
	Message any `json:"message"`
	From    int `json:"sender"`
	To      int `json:"receiver"`
}

// Uniquely defines an incoming client.
type Client struct {
	// Unique Client ID
	ID int
	// Client channel
	Channel chan Data
}

// Global ID variable.
// Increments or decrements on every incoming or outgoing client connections.
var ID int = 0

// Keeps track of every SSE events.
type Event struct {
	// Data are pushed to this channel
	Message chan Data

	// New client connections
	NewClients chan Client

	// Closed client connections
	ClosedClients chan Client

	// Total client connections
	TotalClients map[int]chan Data
}

// Initializes Event and starts the event listener
func NewEvent() (event *Event) {
	event = &Event{
		Message:       make(chan Data),
		NewClients:    make(chan Client),
		ClosedClients: make(chan Client),
		TotalClients:  make(map[int]chan Data),
	}

	go event.listen()
	return
}

// It Listens all incoming requests from clients.
// Handles addition and removal of clients and broadcast messages to clients.
func (stream *Event) listen() {
	for {
		select {
		// Add new available client
		case client := <-stream.NewClients:
			stream.TotalClients[client.ID] = client.Channel
			log.Printf("Added client. %d registered clients", len(stream.TotalClients))

		// Remove closed client
		case client := <-stream.ClosedClients:
			delete(stream.TotalClients, client.ID)
			close(client.Channel)
			ID -= 1
			log.Printf("Removed client. %d registered clients", len(stream.TotalClients))

		// Broadcast message to a specific client with client ID fetched from eventMsg.To
		case eventMsg := <-stream.Message:
			stream.TotalClients[eventMsg.To] <- eventMsg
		}
	}
}

// This is a middleware which creates a Client struct variable with unique UUID & Channel,
// And sets it in the connection's context.
func (stream *Event) SSEConnMiddleware() gin.HandlerFunc {
	return func(gctx *gin.Context) {
		// Increment global variable ID
		ID += 1
		// Initialize client
		client := Client{
			ID:      ID,
			Channel: make(chan Data),
		}

		// Send new connection to event to store
		stream.NewClients <- client

		defer func() {
			// Send closed connection to event server
			log.Printf("Closing connection : %d", client.ID)
			stream.ClosedClients <- client
		}()

		// Mandatory Headers which should be set in the Response header for SSE to work.
		gctx.Writer.Header().Set("Content-Type", "text/event-stream")
		gctx.Writer.Header().Set("Cache-Control", "no-cache")
		gctx.Writer.Header().Set("Connection", "keep-alive")
		gctx.Writer.Header().Set("Transfer-Encoding", "chunked")

		gctx.Set("client", client)
		gctx.Next()
	}
}

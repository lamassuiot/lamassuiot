package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// Define a struct to hold the JSON response
type Response struct {
	Authorized bool `json:"authorized"`
}

// JSON handler function
func jsonHandler(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Authorized: true,
	}

	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/json")

	// Encode the response as JSON and write it to the response writer
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	// Set up the /json route
	http.HandleFunc("/validate", jsonHandler)

	// Start the HTTP server on port 9999
	log.Println("Starting server on :9999")
	if err := http.ListenAndServe(":9999", nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err)
	}
}

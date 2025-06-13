package server

import (
	"github.com/utkarshgupta2804/csrf-project/server/middleware" // Import your custom middleware package.
	"log"   // Import Go's standard logging package.
	"net/http" // Import the standard HTTP package for server functionality.
)

// StartServer starts an HTTP server on the given hostname and port.
func StartServer(hostname string, port string) error {
	// Combine hostname and port into a single host address.
	host := hostname + ":" + port

	// Log a message to indicate the server is starting and listening on the given address.
	log.Printf("Listening on: %s", host)

	// Initialize the HTTP handler by calling your custom middleware's NewHandler function.
	handler := middleware.NewHandler()

	// Register the handler to handle all requests at the root path "/".
	http.Handle("/", handler)

	// Start the HTTP server and listen on the specified host.
	// Returns an error if the server fails to start.
	return http.ListenAndServe(host, nil)
}


package main

import (
	"log" // Package log implements a simple logging package.
	"github.com/utkarshgupta2804/csrf-project/db" // Importing the db package from your project.
	"github.com/utkarshgupta2804/csrf-project/server" // Importing the server package from your project.
	"github.com/utkarshgupta2804/csrf-project/server/middleware/myJwt" // Importing the myJwt middleware package from your project.
)

var host = "localhost" // Define the host address.
var port = "9000" // Define the port number.

func main() {
	// Initialize the database.
	db.InitDB()

	// Initialize the JWT tokens.
	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(jwtErr) // Log and terminate the program if JWT initialization fails.
	}

	// Start the server.
	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr) // Log and terminate the program if server startup fails.
	}
}

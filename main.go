package main

import (
	"log"
	"github.com/utkarshgupta2804/csrf-project/db"
	"github.com/utkarshgupta2804/csrf-project/server"
	"github.com/utkarshgupta2804/csrf-project/server/middleware/myJwt"
)

var host = "localhost"
var port = "9000"

func main() {
	// init the DB
	db.InitDB()

	// init the JWTs
	jwtErr := myJwt.InitJWT()
	if jwtErr!= nil {
		log.Println("Error initializing the JWT's!")
		log.Fatal(jwtErr)
	}

	// start the server
	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr)
	}
}
package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"

	"github.com/dasolerfo/hennge-one-Backend.git/api"
	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
)

func main() {
	fmt.Println("Hola món!")

	config, err := help.LoadConfig(".")
	if err != nil {
		fmt.Println("Error loading config:", err)
	}

	testDB, err := sql.Open(config.DBDriver, config.DBSource)
	if err != nil {
		log.Fatal("Error! No et pots connectar a la base de dades: ", err)
	}

	fmt.Println("Loaded config:", config)

	store := db.NewStore(testDB)

	server, err := api.NewServer(&config, &store)
	if err != nil {
		log.Fatal("Error creating the server:  ", err)
	}

	server.Start()
}

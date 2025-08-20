package main

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/dasolerfo/hennge-one-Backend.git/api"
	db "github.com/dasolerfo/hennge-one-Backend.git/db/model"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
)

func main() {
	fmt.Println("Hola món!")

	config, err := help.LoadConfig("app.env")
	if err != nil {
		fmt.Println("Error loaading config:", err)
	}

	testDB, err := sql.Open(config.DBDriver, config.DBSource)
	if err != nil {
		log.Fatal("Error! No et pots connectar a la base de dades: ", err)
	}

	fmt.Println("Loaded config:", config)

	store := db.NewStore(testDB)

	api.NewServer(&config, &store).Start()

}

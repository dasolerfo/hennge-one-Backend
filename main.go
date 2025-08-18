package main

import (
	"fmt"

	"github.com/dasolerfo/hennge-one-Backend.git/api"
	"github.com/dasolerfo/hennge-one-Backend.git/help"
)

func main() {
	fmt.Println("Hola món!")

	config, err := help.LoadConfig("app.env")
	if err != nil {
		fmt.Println("Error loaading config:", err)
	}

	fmt.Println("Loaded config:", config)

	api.NewServer(&config)

}

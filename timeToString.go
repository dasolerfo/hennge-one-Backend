package main

import "time"

func Main() {
	ProvesAmbElTemps()
}

func ProvesAmbElTemps() {
	t := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	println(t)

	t2, _ := time.Parse(time.RFC3339, t)

	if time.Now().Before(t2) {
		println("Encara és vàlid")
	}

}

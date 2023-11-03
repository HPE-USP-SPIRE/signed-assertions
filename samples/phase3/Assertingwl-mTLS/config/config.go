package config

import (
	"log"

	"github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/env"
)

func init() {
	log.Print("config init")
	// Load '.env' from current working directory.
	env.Load(".cfg")
}

package config

import (
	"log"

	"github.com/hpe-usp-spire/signed-assertions/ID-Mode/api-libs/env"
)

func init() {
	log.Print("config init")

	env.Load(".cfg")
}

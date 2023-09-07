package config

import (
	"log"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/env"
)

func init() {
	log.Print("config init")

	env.Load(".cfg")
}

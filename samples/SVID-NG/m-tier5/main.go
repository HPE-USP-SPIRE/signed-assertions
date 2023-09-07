package main

import (
	"context"
	"log"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/controller"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/m-tier/global"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	global.InitGlobals()

	log.Printf("final init options: %+v", global.Options)
	controller.LSVIDController(ctx)

}

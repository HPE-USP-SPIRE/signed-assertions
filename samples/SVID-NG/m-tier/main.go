package main

import (
	"context"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/m-tier/controller"

)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller.MiddleTierController(ctx)
}

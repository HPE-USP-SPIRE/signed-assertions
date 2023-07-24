package main

import (
	"context"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/m-tier5/controller"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller.MiddleTierController(ctx)
}

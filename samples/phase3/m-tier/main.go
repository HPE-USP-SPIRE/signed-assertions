package main

import (
	"context"

	"github.com/hpe-usp-spire/signed-assertions/phase3/m-tier/controller"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller.MiddleTierController(ctx)
}

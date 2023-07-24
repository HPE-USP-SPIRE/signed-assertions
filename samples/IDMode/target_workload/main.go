package main

import (
	"context"

	"github.com/hpe-usp-spire/signed-assertions/ID-Mode/target-wl/controller"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller.TargetWLController(ctx)
}

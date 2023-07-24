package main

import (
	"context"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/target-wl/controller"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller.TargetWLController(ctx)
}

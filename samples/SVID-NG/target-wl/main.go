package main

import (
	"context"
	// "log"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/target-wl/controller"
	// "github.com/hpe-usp-spire/signed-assertions/SVID-NG/target-wl/local"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller.TargetWLController(ctx)

}

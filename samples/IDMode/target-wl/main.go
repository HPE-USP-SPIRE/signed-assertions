package main

import (
	"context"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/target-wl/controller"
	"github.com/hpe-usp-spire/signed-assertions/IDMode/target-wl/monitoring-prom"
)

func main() {
	go monitor.PrometheusAPI()
	go monitor.UpdateMemoryUsage()
	go monitor.UpdateCPUUsage()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller.TargetWLController(ctx)
}

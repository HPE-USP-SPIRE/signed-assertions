package main

import (

	// dasvid lib test

	// To sig. validation
	_ "crypto/sha256"

	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/controller"
	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/monitoring-prom"
	// Okta
)

func main() {
	go monitor.PrometheusAPI()
	go monitor.UpdateMemoryUsage()
	go monitor.UpdateCPUUsage()
	controller.SubjectWLController()
}

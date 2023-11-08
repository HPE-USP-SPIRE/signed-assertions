package main

import (
	// To sig. validation
	_ "crypto/sha256"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/subject_workload/controller"
	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/subject_workload/monitoring-prom"
	// Okta
)

func main() {
	go monitor.PrometheusAPI()
	go monitor.UpdateMemoryUsage()
	go monitor.UpdateCPUUsage()
	controller.SubjectWLController()
}

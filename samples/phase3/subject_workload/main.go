package main

import (

	// dasvid lib test

	// To sig. validation
	_ "crypto/sha256"

	"github.com/hpe-usp-spire/signed-assertions/phase3/subject_workload/controller"
	// Okta
)

func main() {
	controller.SubjectWLController()
}

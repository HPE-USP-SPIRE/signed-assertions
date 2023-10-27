package main

import (
	// To sig. validation
	_ "crypto/sha256"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/subject_workload/controller"
	// Okta
)

func main() {
	controller.SubjectWLController()
}

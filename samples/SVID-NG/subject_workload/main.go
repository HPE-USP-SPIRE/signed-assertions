package main

import (

	// dasvid lib test

	// To sig. validation
	_ "crypto/sha256"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/subject_workload/controller"
	// Okta
)

func main() {
	controller.SubjectWLController()
}

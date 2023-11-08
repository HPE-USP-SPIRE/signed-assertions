# HPE/USP Transitive Identity & Embedded Claims
This repository is part of HPE/USP Transitive Identity & Embedded Claims project. Details about each component can be found in /doc or in its own directory. The repository is organized as follows:

- **assertgen**: command-line interface (CLI) to perform different functions, like interacting with PoC IdP and executing all poclib functions.
- **doc**: contain the documentation related to the solution.
- **poclib**: prototype of a Go package, containing the token nested scheme functions.
- **samples**: contain all three PoC scenarios and its documentation.

# Project roadmap details
The project roadmap is divided into phases, that have specific objectives.

## Phase 2
In this phase, the objective was to develop a new token scheme allowing to easily append new claims to an existing token. The working group specification document is under development, and can be found in the link [https://docs.google.com/document/d/1nQYV4wf8wiogpxboIVbwtFZyZjLNRejyguHoGZIZLQM]

## Prometheus instrumentalization
This repository includes Prometheus instrumentalization using the Go client. The instrumentation is designed to measure and monitor relevant metrics for the behaviour of the nested token.
It includes a .yml file with the configuration needed for targeting the components data via Prometheus API.
If needed, there is more information available about Prometheus installation on this link: [https://prometheus.io/docs/prometheus/latest/installation/]
# License
This project is licensed under the terms of the Apache 2.0 license. It was developed to support the HPE/USP Transitive Identity & Embedded Claims project. It is not intended to be executed in a production environment without the required security and performance evaluations.

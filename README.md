# HPE/USP Transitive Identity & Embedded Claims
This repository is part of HPE/USP Transitive Identity & Embedded Claims project. Details about each component can be found in /doc or in its own directory. The repository is organized as follows:

- **assertgen**: command-line interface (CLI) to perform different functions, like interacting with PoC IdP and executing all poclib functions.
- **doc**: contain the documentation related to the solution.
- **poclib**: prototype of a Go package, containing the token nested scheme functions.
- **samples**: contain all three PoC scenarios and its documentation.

# Project roadmap details
The project roadmap is divided into phases with specific objectives.

## Phase 2
In this phase, the objective was to develop a new token scheme allowing to easily append new claims to an existing token. The working group specification document is under development, and can be found in the link [https://docs.google.com/document/d/1nQYV4wf8wiogpxboIVbwtFZyZjLNRejyguHoGZIZLQM]

## Phase 1
Project Phase 1 primary objective was to specify and develop a PoC of a JWT-like token (a.k.a. SVID-NG or DA-SVID) created from an OAuth token. More details can be found in [https://docs.google.com/document/d/1fH8XkOKGXGrWy9uk-JXZbyksHejZ2CfB7h6YXetqG_w]

# License
This project is licensed under the terms of the Apache 2.0 license. It was developed to support the HPE/USP Transitive Identity & Embedded Claims project.

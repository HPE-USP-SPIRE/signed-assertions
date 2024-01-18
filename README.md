# HPE/USP Transitive Identity & Embedded Claims

This repository is part of HPE/USP Transitive Identity & Embedded Claims project. Code details about each component can be found in the README of the repective directory in `samples`. The project is divided into 3 phases:

### Phase 1

The primary objective is to specify and develop a JWT-like token (named Delegated Assertions SVID or DA-SVID), which is derived from an OAuth token. In this manner, the DA-SVID can be sent to other workloads instead of the OAuth, which could lead to impersonation problems. More info. [here](https://docs.google.com/document/d/1fH8XkOKGXGrWy9uk-JXZbyksHejZ2CfB7h6YXetqG_w).

### Phase 2

In this phase, the objective is to develop a new token scheme allowing to easily append new claims to an existing token. Essentially, the goal of such a token format is to allow pieces of information (i.e., claims) to be appended to an existing token efficiently and securely, giving support to different use case scenarios (e.g., permission delegation, tracing the path taken by a request since its origin, among others). There are two versions of this nested token: ID Mode and Anonymous Mode. Full documentation [here](https://docs.google.com/document/d/1nQYV4wf8wiogpxboIVbwtFZyZjLNRejyguHoGZIZLQM).

### Phase 3

This phase proposes using the nested token model (phase 2) to develop a new identity document type called a Lightweight SVID (LSVID). When created, this document can be extended with additional relevant information (assertions) and used as a token in multiple distributed use case scenarios, including attestation, authorization delegation, and path tracing. More details [here](https://docs.google.com/document/d/15rfAkzNTQa1ycs-fn9hyIYV5HbznPBsxB-f0vxhNJ24).

## Setting up the environment

### Dependencies

First of all, install the dependencies (some linux packages, Docker, and a modified version of SPIRE):

```
./install_dependencies
```

This project was developed on Debian 11, running Docker 20.10.11 and Go 1.16.9.

### Configuration

This proof-of-concept uses OAuth tokens provided by OKTA (an identity provider). In this section we will describe how to use its services.

First of all fetch yout private IP running:

```
ip a
```

Take note of the IP. You will use it to configure the application. Notice that it might change when you use another network or reboot your computer, so if you don't set it as static you might need to reconfigure the application in the future.

After that, [register](https://developer.okta.com/signup/) to their platform, creating a **developer account**.

When logged in:

1. Go to Applications -> Application in the menu
2. Click on "Create App Integration"
3. Choose "OIDC" as the sign-in method and "Web Application" as the application type
4. Under "Client acting on behalf of a user", check "Authorization Code" and "Implicit (hybrid)". Let the wildcards checkbox disabled.
5. Under "Sign-in redirect URIs", remove whatever is in there and add: http://IP:8080/callback, where IP must be your private IP
6. Under "Controlled Access", check "Allow everyone in your organization to access"

After doing that, manually alter the `.cfg` file here in the root path:

- CLIENT_ID and CLIENT_SECRET: found in your okta application
- ISSUER: substitute the 7 number ID in the URL of the `.cfg` for the ID found in the URL of you okta dashboard (between dev- and -admin)
- HOST_IP and WORKLOAD_IP: substitute the 8 IPs in the `.cfg` for you IP (which must also be set under "Sign-in redirect URIs" in your okta application)

### Running the project in a VM

To be able to correctly run the project using a Virtual Machine, it must be configured to bridged mode. This setting is usually found under the Network Settings.

## Running the application

To execute the application, run:

```
./init
```

You will be asked which model (phase) you want to use.

After prompted that the execution finished successfully, open your browser on localhost:8080.

## Repository's structure

The repository is organized as follows:

- **samples**: contains the code for each phase the respective documentation.
- **poclib**: prototype of a Go package, containing the nested tokens' functions.
- **assertgen**: command-line interface (CLI) to perform different functions, like interacting with the Identity Provider and executing all poclib functions.
- **lib** auxiliary bash scripts used by `install_dependencies`
- **doc**: contains the images used in README files

# License

This project is licensed under the terms of the Apache 2.0 license. It was developed to support the HPE/USP Transitive Identity & Embedded Claims project. It is not intended to be executed in a production environment without the required security and performance evaluations.

# Nested scheme using ID Mode

## Overview

In this signature mode, the assumption is that a TTP identity provider (IdP) is available, enabling workloads to retrieve their own key pair and an identity document (e.g., X509 certificate/SVID). Also, each workload Wn along the path knows the identity of the next workload Wn+1. In this case, they can use its private key to generate signatures, allowing the token creation and appending in a non-repudiable manner. The public key could be taken from any verifiable identity document, with the "signing" key usage field set to true. This is expected to be the case when workloads establish mTLS connections, since the protocol requires certificates to be exchanged. Some implementations may allow that certificate to be extracted from the mTLS layer, whereas others may require it to be fetched at the application layer, as part of the token processing.

In this scenario, Wn may place the whole verifiable identity document as the "audience" claim in the payload, before conveying it to Wn+1. Since such credentials may be large themselves, this may create somewhat large tokens. However, this approach ensures that the receiver can easily verify that each workload identified in the token has signed it along the path without any additional information. Alternatively, Wn may fill the "audience" claim only with Wn+1 public key, sending the identity in a separate document, to allow Wn+1 to be identified further downstream. If the IdP provides a lookup service allowing workloads to fetch public keys from identifiers (and, possibly, cache them), it would be enough to use Wn+1’s identifier as "audience", leading to a multitude of possible trade-offs in terms of bandwidth usage (carrying credentials results in larger assertions), latency (using a lookup service that is contacted for verifying every assertion, without caching, increases latency), and statefulness (caching reduce latency, but are only useful if workloads store credentials locally).

The most suitable choice depends, thus, on the requirements of the target environment. In terms of security, though, there are no trade-offs: any attempt to impersonate some workload W would require access to its private key, or subverting the underlying identity framework to issue fake credentials associated with W’s identifier. Figure 2 contains an example of an application using ID-mode to access user data.

![alt text](https://github.com/HPE-USP-SPIRE/signed-assertions/blob/main/doc/idmode.jpg)

In the example, the process starts with an end user providing an OAuth token (1) to the front end that, by its side, sends it in a request to IdP for a new restricted token. The IdP mints the token tied with the received OAuth token (2), returning it to the front end, followed by its certificate. Then, every workload that needs to use the token in a request should append the mandatory claims and sign it, following the nested scheme, also appending the trusted bundle with its certificate. That is what the front-end (3) and middle-tier (4) do. Finally, the target workload receives the token and trust bundle using the certificates in sequential signature validation (5).

In ID-mode, the objective is to validate all the nested token signatures using the signer certificate. In this mode, when a workload append new claims to an existing token, it set the issuer as its own public key and the audience with the public key of next hop. Then, the it send both token and certificates to the next hop. Each time new information is added to a token, the signer certificate is added to this trust bundle. The validation consists in two steps:

1 - Verify if the issuer of Token(n) is the same ID in the audience of Token(n-1).
2 - Retrieve the public keys from the trust bundle and use it to validate all sequential signatures.

The Figure ID-mode depicts the application of ID-mode in the PoC application:

1.  The user log in application using an OKTA OAuth token
2.  The front-end (subject-wl) send the OAuth token to asserting-wl /ecdsaassertion endpoint, that should return a new ECDSA nested token identifying the user and the workload that is allowed to access in behalf of the user.
3.  The asserting-wl mint the new nested token using ECDSA scheme with its private key, retrieved from SPIRE SVID.
4.  Asserting-wl return to front-end the token and its own certificate.
5.  Before sending the token, Front-end add new claims, specifically the issuer (front-end public key) and audience (middle-tier public key). The resulting payload is signed by front-end using its SVID private key. The token and both certificates (asserting-wl and front-end) are sent to middle-tier.
6.  Similarly, middle-tier add the issuer (middle-tier public key) and audience (Target-wl public key) claims. The resulting payload is signed by middle-tier using its SVID private key. The token and all certificates (asserting-wl, front-end, and middle-tier) are sent to Target-wl.
7.  Finally, Target-wl uses all certificates in the receiving order to validate all sequential signatures, identifying the signers and verifying if the issuer/audience link hold for all hops. If all perform correctly, Target-wl return user data to front-end.

## API

### `/ecdsaassertion <AccessToken>`

| Parameter       | Type   | Required | Description                                                                                |
| --------------- | ------ | -------- | ------------------------------------------------------------------------------------------ |
| `<AccessToken>` | string | yes      | Mint a new ECDSA nested token based in OKTA OAuth token received as AccessToken parameter. |

This endpoint return a new ECDSA nested token. Basically it is the same DA-SVID, but in nested model format, insted JWT (2 part token vs 3 part token).

### `/mintassertion <AccessToken>`

| Parameter       | Type   | Required | Description                                                                                  |
| --------------- | ------ | -------- | -------------------------------------------------------------------------------------------- |
| `<AccessToken>` | string | yes      | Mint a new Schnorr nested token based in OKTA OAuth token received as AccessToken parameter. |

This endpoint returns a new Schnorr nested token. Basically it is the same DA-SVID, but in nested model format, insted JWT (2 part token vs 3 part token).

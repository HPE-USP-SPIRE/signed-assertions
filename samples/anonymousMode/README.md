# Nested scheme using Anonymous Mode

## Overview

In Anonymous Mode, the objective is not to identify each workload in the token flow, but to gran that all signatures are valid and that those signatures were created using the correct private key. In this scenario,a customized concatenation signature scheme is applied, where the private key to be used is part of previous signature. This creates a signature chain and allows validation using a scheme based in [Galindo and Garcia](https://doi.org/10.1007/978-3-642-02384-2_9)'s model.

1. The user logs in the application using an OKTA OAuth token
2. The front-end (subject-wl) sends the OAuth token to asserting-wl /mintassertion endpoint, that should return a new Schnorr nested token identifying the user and the workload that is allowed to access on behalf of the user.
3. The asserting-wl generate a new Schnorr key pair and mint the new nested token using the private key.
4. Asserting-wl returns the token to front-end.
5. Front-end adds the necessary claims, removes part of previous signature and uses it as private key, to generate the new signature. Then, front-end sends the token to middle-tier.
6. Similarly, all the following workloads perform the same routine, adding the necessary claims, removing and using part of previous signature as private key.
7. In the end, the token will be composed of 'n' parts, where only the last is a complete signature, and all previous are partial signatures. Target-wl then use the concatenated signature validation scheme to validate the token.

![Concatenated scheme](https://github.com/HPE-USP-SPIRE/signed-assertions/blob/main/doc/conc_sig.jpg)

As seen in the figure above, the process starts with Wn creating a new token T0 with its private key sk0, containing its public key in “issuer” claim, and sending it to Wn+1 (1). As the digital signatures are composed of two parts, usually called "r" and "s", Wn+1 extracts the "s" part of the previous signature Sn (2), filling the token "issuer" claim with its public key and signing the resulting payload using Sn+1 as private key (3). This scheme results in a token where only the last signature is complete (with "r" and "s" parts), while all previous are partial signatures containing just the "r" part.

It is important to note that in a concatenated scheme there is no need (and it is not possible) to add the public key in "audience" claim, as the correspondent private key depends on the signature generation. Although, it is not a problem: the cryptographic scheme grants that only the correct key, derived from previous signature, can result in a valid concatenated signature.

## API

### `/mintassertion <AccessToken>`

| Parameter       | Type   | Required | Description                                                                                  |
| --------------- | ------ | -------- | -------------------------------------------------------------------------------------------- |
| `<AccessToken>` | string | yes      | Mint a new Schnorr nested token based in OKTA OAuth token received as AccessToken parameter. |

This endpoint returns a new Schnorr nested token. Basically it is the same DA-SVID, but in nested model format, insted JWT (2 part token vs 3 part token).

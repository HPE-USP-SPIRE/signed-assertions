# PocLib
## _Go library to support nested token creation_

PocLib is a Go library that provides functionality for creating, validating, and parsing nested tokens signed using various algorithms, such as ECDSA and Schnorr EdDSA.

PocLib also support SPIFFE/SPIRE integration, allowing the usage of SVID keys and certificates in the assertion/token generation process.

Finally, it can also generate zero-knowledge proofs (ZKP) for RSA signatures,c ommonly used for OAuth tokens. 

# License
This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). It was developed to support the HPE/USP Transitive Identity & Embedded Claims project, and it is important to not that it may require some specific configurations to run properly. The command-line tool assertgen can be used as an example of Poclib usage.


## Features

The main functions available can be divided in:

- SPIRE interaction
- OAuth 2.0 and JWT support and integration
- RSA Zero Knowledge Proof (ZKP) generation and validation
- Nested token functionalities
- Helper functions

### SPIRE interaction

One of the benefits offered by PocLib is the possibility of interacting with SPIRE. It allow applications to use workloads SPIRE private key to sign and validate tokens and assertions. As default, is expected that a SPIRE environment is running locally, for development purposes. The following functionalities can be performed using PocLib:

|Function|Description|
|---|---|
|FetchX509SVID|Fetch the calling workload SVID from SPIRE workload API|
|ReturnSelectors| Return the selectors used on a given PID attestation|

### Support and integration for OAuth 2.0 and JWT 

PocLib also offers a set of functions to support JWT signature and expiration validations. Considering that PoC uses [OKTA](https://www.okta.com/)  OAuth token as part of its implementation, in PocLib there are some helper functions to this specific scenario (e.g., ValidateISS and Token2Vkey). These functions, associated with mintDASVID function, allows to create a new token with a more restricted scope, based on the original OAuth token.

|Function|Description|
|---|---|
|ParseTokenClaims|Parse a JWT token.|
|VerifySignature|Verify JWT token signature. Currently supports RSA.|
|ValidateTokenExp|Validate a JWT token expiration time|
|Mintdasvid|Mint a new token based on OAuth. There are specific arguments that will be added in token payload and must be defined: issuer(iss) = ID of the token issuer; subject (sub) = ID of the workload receiving the authorization; delegated authority (dpa) = Original Oauth issuer; delegated principal (dpr) = The authorizer.| 

### RSA Zero Knowledge Proof (ZKP) generation and validation

Considering the proof of concept implementation, it is important to grant that the new DASVID token actually has an valid OAuth token behind. It can be done using ZKP scheme. The PocLib includes two functions that can be used to generate an ZKP from an existing RSA OAuth token. As this function uses the helper Token2vkey, it demands that token issuer be OKTA, to be able to retrieve the necessary public key. Although, it can easily modified to support other issuers or even to not be necessary to contact the issuer, if the public key is already available. Some parameters, as proof length, should be defined in application cfg file.

|Function|Description|
|---|---|
|GenZKPproof| Generate a ZKP given an existing OAuth token. Return the proof in JSON format|
|VerifyHexProof|Verify a previously generated ZKP. It requires as argument the message, the proof, and the public key|

### Nested token functionalities

The [nested token](ref1) is the token scheme adopted in PocLib. The token can be created using ECDSA, standard or concatenated Schnorr signatures. There are also available the corresponding validation functions.

|Function|Description|
|---|---|
|NewECDSAencode|Generate a new ecdsa signed encoded assertion|
|NewSchnorrencode|Generate a new schnorr signed encoded assertion|
|NewDilithiumencode|Generate a new Dilithium signed encoded assertion|
|ValidateECDSAeassertion|ECDSA token validation from out level to inside (last -> first assertion)|
|Validateschnorrassertion|Standard Schnorr token validation from out level to inside|
|Validategg|Concatenated Schnorr token validation based in Galindo-Garcia model|


### Helper functions

Additionally, PocLib contains a set of helper functions that perform many acessory functions.

|Function|Description|
|---|---|
|PrintAssertion|Print content of an encoded nested token|
|EncodeECDSAPublicKey|Encodes an *ecdsa.PublicKey to PEM format|
|ParseECDSAPublicKey|Parse an ECDSA public key|
|Addkey|Add a key in local Key server (PoC function)|
|getkeys| Retrieve key in kid claim from local Key server (PoC function)|
|Checkaudlink|verify if token0 audience == token 1 issuer|
|String2schsig|Convert a string to schnorr signature|
|Schsig2string|Convert a schnorr signature to string|
|Issuer2schpubkey|Convert issuer claim to kyber.point|
|String2point|Convert a string to kyber.point|
|Point2string|Convert a kyber.point to string|
|Schpubkey2string|Convert a schnorr public key to string|
|JwkEncode|encodes public part of an RSA or ECDSA key into a JWK|
|Jwks2PEM|Convert JWKS to correpondent PEM file|
|extractValue|extract the value for a key from a JSON-formatted string|

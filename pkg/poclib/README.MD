
# PocLib
## _Go package to support nested token creation_

PocLib is a Go package that provides functionality for creating, validating, and parsing nested tokens signed using various algorithms, such as ECDSA and Schnorr EdDSA.

PocLib also support SPIFFE/SPIRE integration, allowing the usage of SVID keys and certificates in the assertion/token generation process.

Finally, it can also generate zero-knowledge proofs (ZKP) for RSA signatures, commonly used for OAuth tokens. 

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
|FetchX509SVID() *x509svid.SVID|Fetch the calling workload SVID from SPIRE workload API|
|ReturnSelectors(pid int) (string, error)| Return the selectors used on a given PID attestation|

### Support and integration for OAuth 2.0 and JWT 

PocLib also offers a set of functions to support JWT signature and expiration validations. Considering that PoC uses [OKTA](https://www.okta.com/)  OAuth token as part of its implementation, in PocLib there are some helper functions to this specific scenario (e.g., ValidateISS and Token2Vkey). These functions, associated with mintDASVID function, allows to create a new token with a more restricted scope, based on the original OAuth token.

|Function|Description|
|---|---|
|ParseTokenClaims(strAT string) map[string]interface{}|Parse a JWT token.|
|VerifySignature(jwtToken string, key JWK) error|Verify JWT token signature. Currently supports RSA.|
|ValidateTokenExp(claims map[string]interface{}) (expresult bool, remainingtime string)|Validate a JWT token expiration time|
|Mintdasvid(kid string, iss string, sub string, dpa string, dpr string, oam []byte, zkp string, key interface{}) string|Mint a new token based on OAuth. There are specific arguments that will be added in token payload and must be defined: issuer(iss) = ID of the token issuer; subject (sub) = ID of the workload receiving the authorization; delegated authority (dpa) = Original Oauth issuer; delegated principal (dpr) = The authorizer.| 

### RSA Zero Knowledge Proof (ZKP) generation and validation

Considering the proof of concept implementation, it is important to grant that the new DASVID token actually has an valid OAuth token behind. It can be done using ZKP scheme. The PocLib includes two functions that can be used to generate an ZKP from an existing RSA OAuth token. As this function uses the helper Token2vkey, it demands that token issuer be OKTA, to be able to retrieve the necessary public key. Although, it can easily modified to support other issuers or even to not be necessary to contact the issuer, if the public key is already available. Some parameters, as proof length, should be defined in application cfg file.

|Function|Description|
|---|---|
|GenZKPproof(OAuthToken string) string| Generate a ZKP given an existing OAuth token. Return the proof in JSON format|
|VerifyHexProof(hexproof string, msg []byte, reckey *C.EVP_PKEY) bool|Verify a previously generated ZKP. It requires as argument the message, the proof, and the public key|

### Nested token functionalities

The [nested token](ref1) is the token scheme adopted in PocLib. The token can be created using ECDSA, standard or concatenated Schnorr signatures. There are also available the corresponding validation functions.

|Function|Description|
|---|---|
|NewECDSAencode(claimset map[string]interface{}, oldmain string, key crypto.Signer) (string, error)|Generate a new ecdsa signed encoded assertion|
|NewSchnorrencode(claimset map[string]interface{}, oldmain string, key kyber.Scalar) (string, error)|Generate a new schnorr signed encoded assertion|
|NewDilithiumencode(claimset map[string]interface{}, oldmain string) (string, error)|Generate a new Dilithium signed encoded assertion|
|ValidateECDSAeassertion|ECDSA token validation from out level to inside (last -> first assertion)|
|Validateschnorrtrace(token string) bool|Schnorr token validation using audience/issuer link validation (use case scenario)|

|Validateschnorrassertion(token string) bool|Standard Schnorr token validation from out level to inside|
|Validategg(token string) bool|Concatenated Schnorr token validation based in Galindo-Garcia model|


### Helper functions

Additionally, PocLib contains a set of helper functions that perform many acessory functions.

|Function|Description|
|---|---|
|Token2vkey(token string, issfield int) *C.EVP_PKEY|Retrieve a public key from IdP and generate a Openssl vkey|
|ValidateISS(issuer string) (uri string, result bool)| Validate if OAuth token issuer is known. Supports OKTA (https://devoktanumber/v1/keys) and Google (https://www.googleapis.com/oauth2/v3/certs) OAuth token.|
|RetrievePrivateKey(path string) interface{}|Extract private key from pem file and return as interface{}|
|RetrievePEMPublicKey(path string) interface{}|Extract public key from pem file and return as interface{}|
|RetrieveDERPublicKey(path string) []byte|Extract public key from pem file and return as []byte|
|RetrieveJWKSPublicKey(path string) JWKS|Extract public key from pem file and return as JWKS|
|ValidateECDSAeassertion(token string) bool| perform ecdsa token validation from out level to inside (last -> first signature)|
|ValidateECDSAIDassertion(token string, key []*ecdsa.PublicKey) bool | Validate ECDSA token using ID-Mode|
|Assertion2vkey(assertion string, issfield int) *C.EVP_PKEY|Retrieve a public key from nested token and generate a Openssl vkey|
|PrintAssertion(assertion string)|Print content of an encoded nested token|
|EncodeECDSAPublicKey(key *ecdsa.PublicKey) ([]byte, error)|Encodes an *ecdsa.PublicKey to PEM format|
|ParseECDSAPublicKey(pubPEM string) (interface{}, error)|Parse an ECDSA public key|
|Addkey(key string) (string, error)|Add a key in local Key server (PoC function)|
|getkeys(message string) ([]string, error)| Retrieve key in kid claim from local Key server (PoC function)|
|Checkaudlink(issmsg string, audmsg string) bool|verify if token0 audience == token 1 issuer|
|String2schsig|Convert a string to schnorr signature|
|String2schsig(message string) (Signature, error)(signature Signature) string|Convert a schnorr signature to string|
|Issuer2schpubkey(message string) kyber.Point|Convert issuer claim to kyber.point|
|String2point(message string) (kyber.Point, error)|Convert a string to kyber.point|
|Point2string(sourcepoint kyber.Point) (string, error)|Convert a kyber.point to string|
|Schpubkey2string(publicKey kyber.Point) string|Convert a schnorr public key to string|
|JwkEncode(pub crypto.PublicKey) (string, error)|encodes public part of an RSA or ECDSA key into a JWK|
|Jwks2PEM(token string, path string)|Convert JWKS to correpondent PEM file|
|AssertionJwks2PEM(token string, path string)|Convert JWKS from assertion to correpondent PEM file|
|ExtractValue(body string, key string) string|extract the value for a key from a JSON-formatted string|

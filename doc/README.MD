# Poclib
## _Go library to support nested token creation_

[![N|Solid](https://cldup.com/dTxpPi9lDf.thumb.png)](https://nodesource.com/products/nsolid)

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

Poclib is a Go library that provides functionality for creating, validating, and parsing nested tokens signed using various algorithms, such as ECDSA and Schnorr EdDSA.

Poclib also support SPIFFE/SPIRE integration, allowing the usage of SVID keys and certificates in the assertion/token generation process.

Finally, it can also generate zero-knowledge proofs (ZKP) for RSA signatures,c ommonly used for OAuth tokens. 

# License
This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0). It was developed to support the HPE/USP Transitive Identity & Embedded Claims project, and it is important to not that it may require some specific configurations to run properly. The command-line tool assertgen can be used as an example of Poclib usage.


## Features

The main features available can be divided in:

- SPIRE interaction
- OAuth 2.0 and JWT support and integration
- RSA Zero Knowledge Proof (ZKP) generation and validation
- Nested token functionalities
- Helper functions

### SPIRE interaction

One of the benefits offered by PocLib is the possibility of interacting with SPIRE. It allow applications to use workloads SPIRE private key to sign and validate tokens and assertions. The following functionalities can be performed using PocLib:

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



---- DRAFT bellow----

# Poclib

Poclib is a Go library that provides functionality for creating, validating, and parsing nested tokens that are signed using various algorithms, such as ECDSA and Schnorr EdDSA.

In addition to these capabilities, Poclib also enables the generation of zero-knowledge proofs (ZKP) for RSA signed tokens, commonly used for OAuth tokens. This allows for the proof of token validity without disclosing the actual signature.

## Using Poclib

Poclib can be integrated directly into other applications by calling its functions within the code.

Additionally, the library also comes with a command-line interface (CLI) tool called assertgen, which can be used to access the functionalities of Poclib.

## Example

```go
package main

import (
	"fmt"
	"log"
	"poclib"
)

func main() {
	// minting a new token
	token, err := poclib.Mint("OAuthtoken")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Token: ", token)
}
```
This example mints a new token, using an OAuth token as input. The generated token will be returned and printed

Note
It's important to check errors when using Poclib methods, there could be some errors like invalid input, failing connection to assert server and others.

# Description of available functions

## ValidateECDSAeassertion

The function ValidateECDSAeassertion takes a token string as an input and returns a Boolean value indicating the validity of the token. It performs validation of a token using ECDSA algorithm, starting from the outermost level to the innermost level.

### Defer timeTrack
The function starts by executing timeTrack(time.Now(), "Validateassertion") which is used to track the execution time of the function, but it is deferred to the end of the function execution.

### Split token into parts
The input token is split into parts using the strings.Split() method. The . character is used as the separator. The resulting parts variable is an array of strings, where each element is a part of the original token.

### Verifying recursively
The function performs verification of the signature and the claims of the token recursively. The outermost claim and signature are verified first and the process continues inward to the innermost claim and signature. For each claim and signature pair (i and j respectively), the following steps are performed:

1. Extract the first payload (parts[i]) and the last signature (parts[j]).
2. Concatenate payload and cleaned parts and take sha256 hash
3. decode signature
4. Extract public key from claim and decode it
5. Verify the signature using ecdsa.VerifyASN1
6. move to next lvl

### Inner lvl Verification
Once the function reaches the innermost level, the following steps are performed:

1. Take the sha256 hash of the innermost claim
2. Decode the signature
3. Retrieve the public key from the claim
4. Verify the signature


### Return Boolean
The function returns **true** if the token is successfully verified or **false** otherwise.

## NewSchnorrencode
The NewSchnorrencode function allows the creation of new Schnorr-signed encoded assertions. This function takes three parameters as input:
- claimset: a map[string]interface{} variable that contains the claims of the assertion.
- oldmain: a string variable that is used when appending new assertion to a previous one. If no oldmain is provided (empty string), the function will generate a simple assertion.
- key: a kyber.Scalar variable that is used to sign the assertion.

The function starts by marshalling the claimset into JSON and then encoding it using the base64.RawURLEncoding method. If no oldmain is provided, the function creates a new Schnorr signature for the payload using the Sign function and the provided key. Then, it writes the signature into a bytes buffer and encodes it using base64.RawURLEncoding. The payload and the signature are joined using "." as separator and returned as the encoded assertion. 

Otherwise, if oldmain is provided, the function appends the new assertion to the previous content and signs all of them using the Sign function and the provided key. 
The payload, oldmain and signature are joined using "." as separator and returned as the encoded assertion. 
In both cases, the function also prints some debugging information about the assertion size, for convenience of developer.


## NewECDSAEncode
The NewECDSAencode function is used for creating a new ECDSA signed encoded assertion. This function takes in 3 arguments:

- claimset: A map of key-value pairs representing the claims being asserted. This is marshalled into a JSON object and encoded into a string (payload).
- oldmain: A string representing the previous encoded assertion that is being appended to (if any).
- key: An ECDSA private key in the form of a crypto.Signer used for signing the encoded assertion.

When this function is called, it first marshals the claimset into a JSON object and encodes it into a string payload. If oldmain is an empty string, the function proceeds to generate a simple assertion. It calculates the SHA-256 hash of the payload and uses the provided private key to sign the hash using ECDSA ASN.1 encoding. The resulting signature is then encoded into a string and joined together with the payload using a "." separator. The resulting encoded assertion is returned along with a nil error value.

Otherwise, the function will append the payload to the previous assertion (oldmain) and sign it. The function will take the string resulting from joining the payload and oldmain with "." separator, calculates the SHA-256 hash of this new message, then sign this hash with the provided private key using ECDSA ASN.1 encoding. The resulting signature is then encoded into a string and joined together with the payload and oldmain using a "." separator, resulting in the final encoded assertion, that is returned.

## ValidateSchnorrAssertion
The function "Validateschnorrassertion" takes in a single input, a string "token" which represents a token that needs to be verified. It uses the Schnorr signature scheme to check the validity of the token. The function uses the defer statement to call the function "timeTrack" with the current time and the string "Validateassertion" as inputs.

The function then splits the input token into parts by using the "strings.Split" function, which splits the token into an array of strings separated by ".". It then performs a recursive verification of the token, going from the outermost level to the innermost level.

The for loop, starting at the i=0 and j= len(parts)-1, in this function verifies all levels of the token except for the innermost level. It extracts the first payload (parts[i]) and last signature (parts[j]), then concatenates the payload and clean strings to form the message. Next, it loads the kyber.Signature from token by calling the function "String2schsig" and passing in the extracted signature. It then extracts the publickey (kyber.Point) from the issuer claim by calling the function "Issuer2schpubkey" and passing in the extracted payload. Finally, it uses the Verify() function to verify the signature using the extracted message and public key, which returns a boolean value indicating whether the signature is valid or not.

Finally, the function verifies the innermost level by extracting the payload and signature from the token, extracting the public key from the issuer claim, and calling the Verify() function to check the validity of the signature. The function then returns the result of this final verification.

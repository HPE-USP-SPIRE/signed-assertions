//	Package developed by SPIFFE Assertions and Tokens WG
//
// to provide, extend and validate Lightweight SVID (LSVID).
// Specification document <https://docs.google.com/document/d/15rfAkzNTQa1ycs-fn9hyIYV5HbznPBsxB-f0vxhNJ24/>
package lsvid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	hash256 "crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type LSVID struct {
	Token  *Token `json:"token"`  // The workload LSVID document
	Bundle *Token `json:"bundle"` // The Trust bundle document
}

type Token struct {
	Nested    *Token   `json:"nested,omitempty"`
	Payload   *Payload `json:"payload"`
	Signature []byte   `json:"signature"`
}

// The set of claims and any existing previous token a given signature refers to.
// It must contain all mandatory claims and optionally any additional
// claim required for the specific use case.
type Payload struct {
	// 	The version claim is meant to set a clear standard,
	// defining how the LSVID should be understood and
	// processed across various platforms.
	//	It identifies the signature scheme and algorithm
	// used in token creation or extension, and may also
	// specify other relevant information for that version.
	// Check Section 4.5.2 <https://docs.google.com/document/d/15rfAkzNTQa1ycs-fn9hyIYV5HbznPBsxB-f0vxhNJ24/>
	Ver int8                   `json:"ver,omitempty"`
	Alg string                 `json:"alg,omitempty"`
	Iat int64                  `json:"iat,omitempty"`
	Iss *IDClaim               `json:"iss,omitempty"`
	Sub *IDClaim               `json:"sub,omitempty"`
	Aud *IDClaim               `json:"aud,omitempty"`
	Dpa string                 `json:"dpa,omitempty"`
	Dpr string                 `json:"dpr,omitempty"`
	Sel map[string]interface{} `json:"sel,omitempty"`
}

// Identity claims encapsulates uniquely involved actors
// (e.g., issuer, audience, or subject).
// This identification can be in the form of a common name, a public key, or an ID.
type IDClaim struct {
	CN string `json:"cn,omitempty"` // e.g.: spiffe://example.org/workload
	PK []byte `json:"pk,omitempty"` // e.g.: VGhpcyBpcyBteSBQdWJsaWMgS2V5
	ID *Token `json:"id,omitempty"` // e.g.: a complete LSVID
}

//	Encode encodes an LSVID struct into a string.
//
//	This function marshals the provided LSVID struct
//
// into JSON and then encodes the JSON byte slice
// to a Base64.RawURLEncoded string, which represents the encoded LSVID.
func Encode(lsvid *LSVID) (string, error) {
	// Marshal the LSVID struct into JSON
	lsvidJSON, err := json.Marshal(lsvid)
	if err != nil {
		return "", fmt.Errorf("error marshaling LSVID to JSON: %v\n", err)
	}

	// Encode the JSON byte slice to Base64.RawURLEncoded string
	encLSVID := base64.RawURLEncoding.EncodeToString(lsvidJSON)

	return encLSVID, nil
}

// Decode decodes a base64 URL-encoded string into an LSVID struct.
//
// This function takes a base64 URL-encoded string, decodes it, and then unmarshals
// the resulting byte slice into an LSVID struct. It returns a pointer to the LSVID struct
// and any error encountered during the process.
func Decode(encLSVID string) (*LSVID, error) {

	// Decode the base64.RawURLEncoded LSVID
	decoded, err := base64.RawURLEncoding.DecodeString(encLSVID)
	if err != nil {
		return nil, fmt.Errorf("error decoding LSVID: %v\n", err)
	}
	fmt.Printf("Decoded LSVID to be unmarshaled: %s\n", decoded)

	// Unmarshal the decoded byte slice into your struct
	var decLSVID LSVID
	err = json.Unmarshal(decoded, &decLSVID)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling LSVID: %v\n", err)
	}
	fmt.Printf("Return vallue: %v\n", decLSVID)
	return &decLSVID, nil
}

// Extend adds a new token to extend an existing LSVID and signs it using the provided key.
//
// This function takes an existing LSVID, a new payload, and a cryptographic signer, and
// creates an extended LSVID by nesting the existing token and the new payload. It then
// marshals the extended token to JSON, signs it, and encodes the signed LSVID to a string.
func Extend(lsvid *LSVID, newPayload *Payload, key crypto.Signer) (string, error) {
	// TODO: Modify the payload struct to support custom claims (maybe using map[string]{interface})
	// Create the extended LSVID structure
	token := &Token{
		Nested:  lsvid.Token,
		Payload: newPayload,
	}

	// Marshal to JSON
	tmpToSign, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("Error generating json: %v\n", err)
	}

	// Sign extlSVID
	hash := hash256.Sum256(tmpToSign)
	s, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("Error generating signed assertion: %v\n", err)
	}

	// Set extLSVID signature
	token.Signature = s

	// Create the extended LSVID
	extLSVID := &LSVID{
		Token:  token,
		Bundle: lsvid.Bundle,
	}

	// Encode signed LSVID
	outLSVID, err := Encode(extLSVID)
	if err != nil {
		return "", fmt.Errorf("Error encoding LSVID: %v\n", err)
	}

	return outLSVID, nil
}

// Validate verifies the validity of a nested token structure.
//
// This function takes a token, verifies the linkage between the audience (Aud) and issuer (Iss)
// claims for each nested token, and validates the signatures using the public keys. It returns
// a boolean indicating whether the validation was successful and any error encountered during
// the validation process.
// TODO: include the root (trust bundle) LSVID as parameter, to validate the inner signature
// TODO: With the bundle being part of LSVID, now it is possible to validate the root.
// TODO: Must include the bundle in validate parameters and the necessary verifications.
func Validate(lsvid *Token) (bool, error) {

	for lsvid.Nested != nil {

		// Check Aud -> Iss link
		if lsvid.Payload.Iss.CN != lsvid.Nested.Payload.Aud.CN {
			return false, fmt.Errorf("Aud -> Iss link validation failed\n")
		}
		fmt.Printf("Aud -> Iss link validation successful!\n")

		// Marshal the LSVID struct into JSON
		tmpLSVID := &Token{
			Nested:  lsvid.Nested,
			Payload: lsvid.Payload,
		}
		lsvidJSON, err := json.Marshal(tmpLSVID)
		if err != nil {
			return false, fmt.Errorf("error marshaling LSVID to JSON: %v\n", err)
		}
		hash := hash256.Sum256(lsvidJSON)

		// Parse the public key
		// TODO: Currently the pk is extracted from the iss lsvid that MUST be present
		// and we are still not validating the trust bundle.
		var issLSVID *Token
		issLSVID = lsvid.Payload.Iss.ID
		for issLSVID.Nested != nil {
			// fmt.Printf("Issuer nested LSVID found! %v\n", issLSVID.Nested)
			issLSVID = issLSVID.Nested
		}
		issLSSubPk, err := x509.ParsePKIXPublicKey(issLSVID.Payload.Sub.PK)
		if err != nil {
			return false, fmt.Errorf("Failed to parse public key: %v\n", err)
		}

		// validate the signature
		log.Printf("Verifying signature created by %s\n", lsvid.Payload.Iss.CN)
		verify := ecdsa.VerifyASN1(issLSSubPk.(*ecdsa.PublicKey), hash[:], lsvid.Signature)
		if verify == false {
			fmt.Printf("\nSignature validation failed!\n\n")
			return false, nil
		}
		log.Printf("Signature validation successful!\n")

		// jump to nested token
		lsvid = lsvid.Nested
	}

	// reached the inner most LSVID.
	// Marshal the LSVID struct into JSON
	lsvidJSON, err := json.Marshal(lsvid.Payload)
	if err != nil {
		return false, fmt.Errorf("error marshaling LSVID to JSON: %v\n", err)
	}
	hash := hash256.Sum256(lsvidJSON)

	// Parse the public key
	issPk, err := x509.ParsePKIXPublicKey(lsvid.Payload.Iss.PK)
	if err != nil {
		return false, fmt.Errorf("Failed to parse public key: %v\n", err)
	}
	log.Printf("Public key to be used: %s", issPk)

	log.Printf("Verifying signature created by %s\n", lsvid.Payload.Iss.CN)
	verify := ecdsa.VerifyASN1(issPk.(*ecdsa.PublicKey), hash[:], lsvid.Signature)
	if verify == false {
		fmt.Printf("\nSignature validation failed!\n\n")
		return false, nil
	}

	return true, nil
}

// FetchLSVID retrieves a JWT-SVID (LSVID) from a workload API.
//
// This function connects to the SPIRE agent using the provided socket path, fetches
// an X509-SVID to obtain the client ID, creates a JWT source, and then fetches a JWT-SVID
// for the given client ID. It returns the LSVID as a string and any error encountered
// during the process.
func FetchLSVID(ctx context.Context, socketPath string) (string, error) {

	// Fetch claims data
	clientSVID, err := FetchSVID(ctx, socketPath)
	if err != nil {
		return "", fmt.Errorf("Unable to fetch X509 SVID: %v\n", err)
	}
	clientID := clientSVID.ID.String()

	source, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return "", fmt.Errorf("Unable to create JWTSource %v\n", err)
	}
	defer source.Close()

	fetchLSVID, err := source.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: clientID,
	})
	if err != nil {
		return "", fmt.Errorf("Unable to Fetch LSVID %v\n", err)
	}

	return fmt.Sprintf("%s", fetchLSVID.LSVID.Svid), nil
}

//	Cert2LSR creates an LSVID payload from a given x509 certificate.
//
//	This function fetches the client SVID, extracts the client ID, generates an encoded
//
// public key from the provided x509 certificate, and creates an LSVID payload based on
// the LSVID specification.
// PS: Payload claims are based in LSVID spec doc
func Cert2LSR(ctx context.Context, socketPath string, cert *x509.Certificate, audience string) (*Payload, error) {

	clientSVID, err := FetchSVID(ctx, socketPath)
	if err != nil {
		return &Payload{}, fmt.Errorf("Unable to fetch X509 SVID: %v\n", err)
	}
	clientID := clientSVID.ID.String()

	// generate encoded public key
	tmppk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return &Payload{}, err
	}
	// pubkey :=  base64.RawURLEncoding.EncodeToString(tmppk)

	// Versioning needs TBD. For poc, considering vr = 1
	if cert.URIs[0] == nil {
		return &Payload{}, fmt.Errorf("No certificate URI: %v", err)
	}
	sub := cert.URIs[0].String()
	// Create LSVID payload
	lsvidPayload := &Payload{
		Ver: 1,
		Alg: "ES256",
		Iat: time.Now().Round(0).Unix(),
		Iss: &IDClaim{
			CN: clientID,
		},
		Sub: &IDClaim{
			CN: sub,
			PK: tmppk,
		},
		Aud: &IDClaim{
			CN: audience,
		},
	}

	return lsvidPayload, nil
}

//	FetchSVID retrieves the workload X509 SVID from the SPIRE agent.
//	This function creates a workloadapi.X509Source to connect
//
// to the SPIRE Workload API using the provided socket path.
//
//	It then fetches the X509 SVID, which contains the client ID and
//
// the corresponding X509 certificate.
// Used in fetchLSVID to retrieve the clientID.
// TODO: stop using this requires less imports. Keep it simple.
func FetchSVID(ctx context.Context, socketPath string) (*x509svid.SVID, error) {

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("Unable to create X509Source: %v\n", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("Unable to fetch SVID: %v\n", err)
	}

	return svid, nil
}

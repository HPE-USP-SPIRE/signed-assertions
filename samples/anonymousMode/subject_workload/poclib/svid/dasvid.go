//+build linux,cgo 
package svid
/*
#cgo CFLAGS: -g -Wall -m64 -I${SRCDIR}
#cgo pkg-config: --static libssl libcrypto
#cgo LDFLAGS: -L${SRCDIR} 

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "../svid/rsa_sig_proof.h"
#include "../svid/rsa_bn_sig.h"
#include "../svid/rsa_sig_proof_util.h"


*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	// To sig. validation
	"crypto"
	"crypto/rsa"
	hash256 "crypto/sha256"
	"encoding/binary"
	"math/big"

	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	// // to retrieve PrivateKey
	"bufio"
	"crypto/x509"
	"encoding/pem"

	// To JWT generation
	"flag"

	mint "github.com/golang-jwt/jwt"

	// To fetch SVID
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// To Dilithium sig.
	"crypto/ecdsa"
	"crypto/rand"
	"io/ioutil"

	"github.com/cloudflare/circl/sign/dilithium"
	"go.dedis.ch/kyber/v3"

	// To selectors assertion
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/proto/spire/common"
)

type SVID struct {
	// ID is the SPIFFE ID of the X509-SVID.
	ID spiffeid.ID

	// Certificates are the X.509 certificates of the X509-SVID. The leaf
	// certificate is the X509-SVID certificate. Any remaining certificates (
	// if any) chain the X509-SVID certificate back to a X.509 root for the
	// trust domain.
	Certificates []*x509.Certificate

	// PrivateKey is the private key for the X509-SVID.
	PrivateKey crypto.Signer
}

type X509Context struct {
	// SVIDs is a list of workload X509-SVIDs.
	SVIDs []*x509svid.SVID

	// Bundles is a set of X.509 bundles.
	Bundles *x509bundle.Set
}

type JWKS struct {
	Keys []JWK
}

type JWK struct {
	Alg string
	Kty string
	X5c []string
	N   string
	E   string
	Kid string
	X5t string
}

type algtype struct {
	Kid string
	alg string
	typ string
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s execution time is %s", name, elapsed)
}

// Verify JWT token signature.
// currently supporting RSA. Adding new switch cases to support ECDSA and HMAC.
func VerifySignature(jwtToken string, key JWK) error {
	defer timeTrack(time.Now(), "Verify Signature")

	parts := strings.Split(jwtToken, ".")
	message := []byte(strings.Join(parts[0:2], "."))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	log.Printf("DASVID token identified. Checking header... ")
	decodedheader, _ := base64.RawURLEncoding.DecodeString(parts[0])
	jsonheader := string(decodedheader)
	algtype := ExtractValue(jsonheader, "alg")

	switch {
	//  TODO.
	//  Kid added in mint function. Verify possible benefits here. If none, remove from there.
	case (algtype == "RS256"), (key.Kty == "RSA"):
		{
			log.Printf("Success! Key type %s is supported!", algtype)
			n, _ := base64.RawURLEncoding.DecodeString(key.N)
			e, _ := base64.RawURLEncoding.DecodeString(key.E)
			z := new(big.Int)
			z.SetBytes(n)
			//decoding key.E returns a three byte slice, https://golang.org/pkg/encoding/binary/#Read and other conversions fail
			//since they are expecting to read as many bytes as the size of int being returned (4 bytes for uint32 for example)
			var buffer bytes.Buffer
			buffer.WriteByte(0)
			buffer.Write(e)
			exponent := binary.BigEndian.Uint32(buffer.Bytes())
			publicKey := &rsa.PublicKey{N: z, E: int(exponent)}

			// Only small messages can be signed directly; thus the hash of a
			// message, rather than the message itself, is signed.
			hasher := crypto.SHA256.New()
			hasher.Write(message)

			err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hasher.Sum(nil), signature)
			return err
		}
	default:
		{
			log.Printf("Error in signature verification: Algorithm %s not supported!", algtype)
			return errors.New("Algorithm not supported!")
		}
	}
}

// Mint a new DASVID
func Mintdasvid(kid string, iss string, sub string, dpa string, dpr string, oam []byte, zkp string, key interface{}) string {
	defer timeTrack(time.Now(), "Mintdasvid")

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Set issue and exp time
	issue_time := time.Now().Round(0).Unix()
	exp_time := time.Now().Add(time.Minute * 2).Round(0).Unix()

	// Declaring flags
	issuer := flag.String("iss", iss, "issuer(iss) = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload")
	assert := flag.Int64("aat", issue_time, "asserted at(aat) = time at which the assertion made in the DA-SVID was verified by the asserting workload")
	exp := flag.Int64("exp", exp_time, "expiration time(exp) = as small as reasonably possible, issue time + 1s by default.")
	subj := flag.String("sub", sub, "subject (sub) = the identity about which the assertion is being made. Subject workload's SPIFFE ID.")
	dlpa := flag.String("dpa", dpa, "delegated authority (dpa) = ")
	dlpr := flag.String("dpr", dpr, "delegated principal (dpr) = The Principal")

	// Build Token
	var token *mint.Token

	if (oam != nil) && (zkp != "") {
		oam := flag.String("oam", string(oam), "Oauth token without signature part")
		proof := flag.String("zkp", zkp, "OAuth Zero-Knowledge-Proof")

		token = mint.NewWithClaims(mint.SigningMethodRS256, mint.MapClaims{
			"exp": *exp,
			"iss": *issuer,
			"aat": *assert,
			"sub": *subj,
			"dpa": *dlpa,
			"dpr": *dlpr,
			"zkp": map[string]interface{}{
				"msg":   oam,
				"proof": proof,
			},
			"iat": issue_time,
		})

	} else {
		token = mint.NewWithClaims(mint.SigningMethodRS256, mint.MapClaims{
			"exp": *exp,
			"iss": *issuer,
			"aat": *assert,
			"sub": *subj,
			"dpa": *dlpa,
			"dpr": *dlpr,
			"iat": issue_time,
		})
	}

	flag.Parse()

	// Sign Token
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(key)
	if err != nil {
		log.Printf("Error generating JWT: %v", err)
	}

	return tokenString
}

// Parse a JWT token like content (3 parts)
func ParseTokenClaims(strAT string) map[string]interface{} {
	// defer timeTrack(time.Now(), "Parse token claims")

	// Parse access token without validating signature
	token, _, err := new(mint.Parser).ParseUnverified(strAT, mint.MapClaims{})
	if err != nil {
		log.Printf("Error parsing JWT claims: %v", err)
	}
	claims, _ := token.Claims.(mint.MapClaims)

	// fmt.Println(claims)
	return claims
}

// Validate a JWT token Exp
func ValidateTokenExp(claims map[string]interface{}) (expresult bool, remainingtime string) {
	// defer timeTrack(time.Now(), "Validate token exp")

	tm := time.Unix(int64(claims["exp"].(float64)), 0)
	remaining := tm.Sub(time.Now())

	if remaining > 0 {
		expresult = true
	} else {
		expresult = false
	}

	return expresult, remaining.String()

}

// Generate a ZKP proof for RSA OAuth token
func GenZKPproof(OAuthToken string) string {
	defer timeTrack(time.Now(), "Generate ZKP")

	var bigN, bigE, bigSig, bigMsg *C.BIGNUM
	var vkey *C.EVP_PKEY

	parts := strings.Split(OAuthToken, ".")

	// Generate OpenSSL vkey using token
	vkey = Token2vkey(OAuthToken, 0)

	// Generate signature BIGNUM
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		log.Printf("Error collecting signature: %v", err)
	}
	sig_len := len(signature)
	sig_C := C.CBytes(signature)
	defer C.free(unsafe.Pointer(sig_C))
	bigSig = C.BN_new()
	bigsigresult := C.rsa_sig_extract_bn(&bigSig, (*C.uchar)(sig_C), (C.size_t)(sig_len))
	if bigsigresult != 1 {
		log.Printf("Error generating bigMSG")
	}

	// Gen message BIGNUM
	message := []byte(strings.Join(parts[0:2], "."))
	msg_len := len(message)
	msg_C := C.CBytes(message)
	defer C.free(unsafe.Pointer(msg_C))
	bigMsg = C.BN_new()
	bigmsgresult := C.rsa_msg_evp_extract_bn(&bigMsg, (*C.uchar)(msg_C), (C.uint)(msg_len), vkey)
	if bigmsgresult != 1 {
		log.Printf("Error generating bigMSG")
	}

	// Extract bigN and bigE from VKEY
	bigN = C.BN_new()
	bigE = C.BN_new()
	C.rsa_vkey_extract_bn(&bigN, &bigE, vkey)

	// Verify signature correctness
	sigver := C.rsa_bn_ver(bigSig, bigMsg, bigN, bigE)
	if sigver != 1 {
		log.Printf("Error in signature verification\n")
	}

	// Generate Zero Knowledge Proof
	proof_len, _ := strconv.Atoi(os.Getenv("PROOF_LEN"))
	proof := C.rsa_sig_proof_prove((C.int)(sig_len*8), (C.int)(proof_len), bigSig, bigE, bigN)
	if proof == nil {
		log.Printf("Error creating proof\n")
	}

	// // Check proof correctness
	// sigproof := C.rsa_evp_sig_proof_ver(proof, (*C.uchar)(msg_C), (C.uint)(msg_len), vkey)
	// if( sigproof != 1) {
	//     log.Printf("Failed verifying sigproof ! \n")
	// }

	// results is a JSON with two arrays: proofp and proofc, containing 'n' pairs of key:value, where each value represents one proof.
	// we can send the JSON over network and reconstruct the proof using it
	results := C.rsa_sig_proof2hex((C.int)(proof_len), proof)
	goresults := C.GoString(results)
	// fmt.Println("rsa_sig_proof2hex: ", goresults)

	// Verify generated HexProof
	hexresult := VerifyHexProof(goresults, message, vkey)
	if hexresult == false {
		log.Fatal("Error verifying hexproof!!")
	}

	C.EVP_PKEY_free(vkey)
	return goresults
}

// Verify generated proof
func VerifyHexProof(hexproof string, msg []byte, reckey *C.EVP_PKEY) bool {
	defer timeTrack(time.Now(), "Verify ZKP")

	var bigN, bigE, bigMsg *C.BIGNUM
	bigN = C.BN_new()
	bigE = C.BN_new()
	bigMsg = C.BN_new()

	proof_len, _ := strconv.Atoi(os.Getenv("PROOF_LEN"))

	// reconstruct proof
	hexproof_C := C.CString(hexproof)
	reconstructed := C.rsa_sig_hex2proof((C.int)(proof_len), (*C.char)(hexproof_C))
	if reconstructed == nil {
		fmt.Println("Error: reconstructed nil")
	}

	// Generate bigMSG
	msg_len := len(msg)
	msg_C := C.CBytes(msg)
	defer C.free(unsafe.Pointer(msg_C))

	bigmsgresult := C.rsa_msg_evp_extract_bn(&bigMsg, (*C.uchar)(msg_C), (C.uint)(msg_len), reckey)
	if bigmsgresult != 1 {
		log.Printf("Error generating bigMSG")
	}

	// Extract bigN and bigE from VKEY
	C.rsa_vkey_extract_bn(&bigN, &bigE, reckey)

	// Check proof correctness
	proofcheck := C.rsa_sig_proof_ver(reconstructed, bigMsg, bigE, bigN)
	if proofcheck == 0 {
		log.Printf("VerifyHexProof failed verifying proof :( \n")
		return false
	} else if proofcheck == -1 {
		log.Printf("VerifyHexProof found an error verifying proof :( \n")
		return false
	}
	log.Printf("VerifyHexProof successfully verified the proof! :) \n")
	return true
}

// Receive a JWT token, identify the original OAuth token issuer and contact endpoint to retrieve JWK public key.
// Convert the JWT to PEM and finally PEM to OpenSSL vkey.
// Oauth issuer field: 0 - iss (OAuth token); 1 - dpa (DA-SVID token);
func Token2vkey(token string, issfield int) *C.EVP_PKEY {
	// defer timeTrack(time.Now(), "Token2vkey")

	var vkey *C.EVP_PKEY
	var filepem *C.FILE

	// extract OAuth token issuer (i.e. issuer in OAuth, dpa in DA-SVID) and generate path to /keys endpoint
	tokenclaims := ParseTokenClaims(token)

	var issuer string
	if issfield == 0 {
		issuer = fmt.Sprintf("%v", tokenclaims["iss"])
		log.Printf("OAuth issuer claim: %s", issuer)
	} else if issfield == 1 {
		issuer = fmt.Sprintf("%v", tokenclaims["dpa"])
		log.Printf("DASVID issuer claim: %s", issuer)
	} else {
		log.Fatal("No issuer field informed.")
	}

	uri, result := ValidateISS(issuer)
	if result != true {
		log.Fatal("OAuth token issuer not identified!")
	}

	resp, err := http.Get(uri)
	defer resp.Body.Close()

	out, err := os.Create("./keys/oauth.json")
	if err != nil {
		log.Printf("Error creating Oauth public key cache file: %v", err)
	}
	defer out.Close()
	io.Copy(out, resp.Body)

	Jwks2PEM(token, "./keys/oauth.json")

	// Open OAuth PEM file containing Public Key
	filepem = C.fopen((C.CString)(os.Getenv("PEM_PATH")), (C.CString)("r"))
	if filepem == nil {
		log.Fatal("Error opening PEM file!")
	}

	log.Printf("filepem generated: %v", filepem)

	// Load key from PEM file to VKEY
	vkey = nil
	C.PEM_read_PUBKEY(filepem, &vkey, nil, nil)

	log.Printf("vkey generated: %v", vkey)
	C.fclose(filepem)

	return vkey
}

// Receive a JWT token, identify the original OAuth token issuer and contact endpoint to retrieve JWK public key.
// Convert the JWT to PEM and finally PEM to OpenSSL vkey.
//
// Oauth issuer field: 0 - iss (OAuth token); 1 - dpa (DA-SVID token);
func Assertion2vkey(assertion string, issfield int) *C.EVP_PKEY {
	// defer timeTrack(time.Now(), "Token2vkey")

	var vkey *C.EVP_PKEY
	var filepem *C.FILE

	// extract OAuth token issuer (i.e. issuer in OAuth, dpa in DA-SVID) and generate path to /keys endpoint
	// assertionclaims := ParseTokenClaims(token)
	parts := strings.Split(assertion, ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[0])
	log.Printf(string(claims))
	var assertionclaims map[string]interface{}

	err := json.Unmarshal(claims, &assertionclaims)
	if err != nil {
		log.Fatalf("error:", err)
	}

	var issuer string
	if issfield == 0 {
		issuer = fmt.Sprintf("%v", assertionclaims["iss"])
		log.Printf("OAuth issuer claim: %s", issuer)
	} else if issfield == 1 {
		issuer = fmt.Sprintf("%v", assertionclaims["dpa"])
		log.Printf("DASVID issuer claim: %s", issuer)
	} else {
		log.Fatal("No issuer field informed.")
	}

	uri, result := ValidateISS(issuer)
	if result != true {
		log.Fatal("OAuth token issuer not identified!")
	}

	resp, err := http.Get(uri)
	defer resp.Body.Close()

	out, err := os.Create("./keys/oauth.json")
	if err != nil {
		log.Printf("Error creating Oauth public key cache file: %v", err)
	}
	defer out.Close()
	io.Copy(out, resp.Body)

	AssertionJwks2PEM(assertion, "./keys/oauth.json")

	// Open OAuth PEM file containing Public Key
	filepem = C.fopen((C.CString)(os.Getenv("PEM_PATH")), (C.CString)("r"))
	if filepem == nil {
		log.Fatal("Error opening PEM file!")
	}

	// log.Printf("filepem generated: %v", filepem)

	// Load key from PEM file to VKEY
	vkey = nil
	C.PEM_read_PUBKEY(filepem, &vkey, nil, nil)

	// log.Printf("vkey generated: %v", vkey)
	C.fclose(filepem)

	return vkey
}

// Validate if OAuth token issuer is known.
// Supported OAuth tokens and public key endpoint:
// OKTA:
// https://<Oauth token issuer>+"/v1/keys"
//
// Google:
// https://www.googleapis.com/oauth2/v3/certs
//
// TODO: Move supported type list to a config file, making easier to add new ones.
func ValidateISS(issuer string) (uri string, result bool) {
	// defer timeTrack(time.Now(), "ValidateISS")
	// TODO Add error handling
	if issuer == "accounts.google.com" {
		log.Printf("Google OAuth token identified!")
		return "https://www.googleapis.com/oauth2/v3/certs", true
	} else {
		//  In this prototype we consider that if it is not a Google token its OKTA
		log.Printf("OKTA OAuth token identified!")
		return issuer + "/v1/keys", true
	}
	return "", false
}

func RetrievePrivateKey(path string) interface{} {
	// defer timeTrack(time.Now(), "RetrievePrivateKey")
	// Open file containing private Key
	privateKeyFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening private key file: %v", err)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	pemdata, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	// Extract Private Key
	// updated to use RSA since key used will not be fetched from SPIRE
	privateKeyImported, err := x509.ParsePKCS1PrivateKey(pemdata.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}
	return privateKeyImported
}

func RetrievePEMPublicKey(path string) interface{} {
	// defer timeTrack(time.Now(), "RetrievePEMPublicKey")
	// Open file containing public Key
	publicKeyFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening public key file: %v", err)
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	block, _ := pem.Decode(pembytes)
	if block == nil {
		log.Fatalf("No PEM key found: %v", err)
		// os.Exit(1)
	}

	var publicKey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatalf("error", err)
		}

	default:
		log.Fatalf("Unsupported key type %q", block.Type)
	}

	// Return raw public key (N and E) (PEM)
	return publicKey

}

func RetrieveDERPublicKey(path string) []byte {
	// defer timeTrack(time.Now(), "RetrieveDERPublicKey")

	// Open file containing public Key
	publicKeyFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening public key file: %v", err)
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	block, _ := pem.Decode(pembytes)
	if block == nil {
		log.Fatalf("No key found: %v", err)
	}

	var publicKey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatalf("error", err)
		}

	default:
		log.Fatalf("Unsupported key type %q", block.Type)
	}

	// Return DER
	marshpubic, _ := x509.MarshalPKIXPublicKey(publicKey)
	// log.Printf("Success returning DER: ", marshpubic)

	return marshpubic
}

func RetrieveJWKSPublicKey(path string) JWKS {
	// defer timeTrack(time.Now(), "RetrieveJWKSPublicKey")
	// Open file containing the keys obtained from /keys endpoint
	// NOTE: A cache file could be useful
	jwksFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error reading jwks file: %v", err)
	}

	// Decode file and retrieve Public key from Okta application
	dec := json.NewDecoder(jwksFile)
	var jwks JWKS

	if err := dec.Decode(&jwks); err != nil {
		log.Fatalf("Unable to read key: %s", err)
	}

	return jwks
}

// Fetch workload X509 SVID
func FetchX509SVID() *x509svid.SVID {
	// defer timeTrack(time.Now(), "Fetchx509svid")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(os.Getenv("SOCKET_PATH"))))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}

	return svid
}

// returnSelectors return selectors of a given PID
func ReturnSelectors(pid int) (string, error) {
	defer timeTrack(time.Now(), "returnSelectors")

	logg, _ := test.NewNullLogger()

	// hclpPluginConfig := catalog.HCLPluginConfigMap{
	// 	"KeyManager":   {},
	// 	"NodeAttestor": {},
	// 	// "WorkloadAttestor": map[string]scatalog.Config.HCLPluginConfig{
	// 	// 	"docker": catalog.Config.HCLPluginConfig{},
	// 	// 	"unix":   catalog.Config.HCLPluginConfig{},
	// 	// },
	// }
	// set config parameters
	minimalConfig := func() catalog.Config {
		return catalog.Config{
			Log: logg,
			//PluginConfig: hclpPluginConfig,
		}
	}
	config := minimalConfig()

	// retrieve attestators
	repo, _ := catalog.Load(context.Background(), config)
	plugins := repo.GetWorkloadAttestors()

	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	// Attest
	for _, p := range plugins {
		go func(p workloadattestor.WorkloadAttestor) {
			if selectors, err := p.Attest(context.Background(), pid); err == nil {
				sChan <- selectors
			} else {
				errChan <- err
			}
		}(p)
	}

	// Collect the results
	selectors := []*common.Selector{}
	for i := 0; i < len(plugins); i++ {
		select {
		case s := <-sChan:
			selectors = append(selectors, s...)
		case err := <-errChan:
			log.Fatal("Failed to collect all selectors for PID", err)
		}
	}
	result, err := json.Marshal(selectors)
	if err != nil {
		log.Fatal("Error marshalling selectors", err)
	}

	return fmt.Sprintf("%s", result), nil
}

// extract the value for a key from a JSON-formatted string
// body - the JSON-response as a string. Usually retrieved via the request body
// key - the key for which the value should be extracted
// returns - the value for the given key
func ExtractValue(body string, key string) string {
	keystr := "\"" + key + "\":[^,;\\]}]*"
	r, _ := regexp.Compile(keystr)
	match := r.FindString(body)
	keyValMatch := strings.Split(match, ":")
	return strings.ReplaceAll(keyValMatch[1], "\"", "")
}

// Convert JWKS to correpondent PEM file
func Jwks2PEM(token string, path string) {
	defer timeTrack(time.Now(), "Jwks2PEM")

	pubkey := RetrieveJWKSPublicKey(path)

	// Verify token signature using extracted Public key
	for i := 0; i < len(pubkey.Keys); i++ {

		err := VerifySignature(token, pubkey.Keys[i])
		if err == nil {
			Pubkbey2PEMfile(pubkey.Keys[i])
		} else {
			log.Printf("signautre verification error using key %s", pubkey.Keys[i].Kty)
		}
	}
}

func Pubkbey2PEMfile(pubkey JWK) {

	if pubkey.Kty != "RSA" {
		log.Printf("invalid key type:", pubkey.Kty)
	}

	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(pubkey.N)
	if err != nil {
		log.Printf(fmt.Sprintf("%s", err))
	}
	e := 0

	// The default exponent is usually 65537, so just compare the
	// base64 for [1,0,1] or [0,1,0,1]
	if pubkey.E == "AQAB" || pubkey.E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		log.Printf("need to decode e:", pubkey.E)
	}

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}

	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		log.Printf(fmt.Sprintf("%s", err))
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	var out bytes.Buffer
	pem.Encode(&out, block)
	fmt.Println("Generated public key in PEM format: ", out.String())

	// Create output file
	file, err := os.Create("./keys/oauth.pem")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Writing PEM file...")
	_, err = file.Write(out.Bytes())
	if err != nil {
		log.Fatal("Error writing PEM file: ", err)
	}
	file.Close()

}
func AssertionJwks2PEM(token string, path string) {
	defer timeTrack(time.Now(), "AssertionJwks2PEM")

	pubkey := RetrieveJWKSPublicKey(path)

	fmt.Println("Creating pubkey: ", pubkey.Keys[0].Kty)

	if pubkey.Keys[0].Kty != "RSA" {
		log.Fatal("invalid key type:", pubkey.Keys[0].Kty)
	}

	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(pubkey.Keys[0].N)
	if err != nil {
		log.Fatal(err)
	}

	e := 0
	// The default exponent is usually 65537, so just compare the
	// base64 for [1,0,1] or [0,1,0,1]
	if pubkey.Keys[0].E == "AQAB" || pubkey.Keys[0].E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		log.Fatal("need to decode e:", pubkey.Keys[0].E)
	}

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}

	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		log.Fatal(err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	var out bytes.Buffer
	pem.Encode(&out, block)
	fmt.Println("Generated public key in PEM format: ", out.String())

	// Create output file
	file, err := os.Create("./keys/oauth.pem")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Writing PEM file...")
	_, err = file.Write(out.Bytes())
	if err != nil {
		log.Fatal("Error writing PEM file: ", err)
	}
	file.Close()

}

// jwkEncode encodes public part of an RSA or ECDSA key into a JWK.
// The result is also suitable for creating a JWK thumbprint.
// https://tools.ietf.org/html/rfc7517
func JwkEncode(pub crypto.PublicKey) (string, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.3.1
		n := pub.N
		e := big.NewInt(int64(pub.E))
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
		), nil
	case *ecdsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.2.1
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		), nil
	}
	return "", nil
}

// Function to perform ecdsa token validation from out level to inside (last -> first assertion)
func ValidateECDSAeassertion(token string) bool {
	defer timeTrack(time.Now(), "Validateassertion")

	parts := strings.Split(token, ".")

	//  Verify recursively all lvls except most inner
	var i = 0
	var j = len(parts) - 1
	for i < len(parts)/2 && (i+1 < j-1) {
		// Extract first payload (parts[i]) and last signature (parts[j])
		clean := strings.Join(strings.Fields(strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")), ".")
		hash := hash256.Sum256([]byte(parts[i] + "." + clean))
		signature, err := base64.RawURLEncoding.DecodeString(parts[j])
		if err != nil {
			fmt.Printf("Error decoding signature: %s\n", err)
			return false
		}

		// retrieve key from IdP
		keys, err := getkeys(parts[i])
		if err != nil {
			fmt.Printf("Error decoding signature: %s\n", err)
			return false
		}

		fmt.Printf("Claim     %d: %s\n", i, parts[i])
		fmt.Printf("Signature %d: %s\n", j, parts[j])

		// Search for a valid key
		var z = 0
		for z < len(keys)-1 {
			cleankeys := strings.Trim(fmt.Sprintf("%s", keys[z]), "\\")

			var tmpkey map[string]interface{}
			json.Unmarshal([]byte(cleankeys), &tmpkey)
			pkey, _ := base64.RawURLEncoding.DecodeString(fmt.Sprintf("%s", tmpkey["Pkey"]))
			finallykey, _ := ParseECDSAPublicKey(fmt.Sprintf("%s", pkey))

			verify := ecdsa.VerifyASN1(finallykey.(*ecdsa.PublicKey), hash[:], signature)
			if verify == true {
				fmt.Printf("Signature successfully validated!\n\n")
				z = len(keys) - 1
			} else {
				fmt.Printf("\nSignature validation failed!\n\n")
				if z == len(keys)-2 {
					fmt.Printf("\nSignature validation failed! No keys remaining!\n\n")
					return false
				}
			}
			z++
		}
		i++
		j--
	}

	// Verify Inner lvl

	// Verify if signature j is valid to parts[i] (there is no remaining previous assertion)
	hash := hash256.Sum256([]byte(parts[i]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[j])
	if err != nil {
		fmt.Printf("Error decoding signature: %s\n", err)
		return false
	}

	// retrieve key from IdP
	keys, err := getkeys(parts[i])
	if err != nil {
		fmt.Printf("Error decoding signature: %s\n", err)
		return false
	}

	// fmt.Printf("Received Keys: %s\n", keys)
	fmt.Printf("Claim     %d: %s\n", i, parts[i])
	fmt.Printf("Signature %d: %s\n", j, parts[j])

	// verify if any of the received keys is valid
	var z = 0
	for z < len(keys)-1 {
		cleankeys := strings.Trim(fmt.Sprintf("%s", keys[z]), "\\")

		var lastkey map[string]interface{}
		json.Unmarshal([]byte(cleankeys), &lastkey)
		fmt.Printf("Search kid: %s\n", lastkey["Kid"])
		key, _ := base64.RawURLEncoding.DecodeString(fmt.Sprintf("%s", lastkey["Pkey"]))
		finallykey, _ := ParseECDSAPublicKey(fmt.Sprintf("%s", key))

		verify := ecdsa.VerifyASN1(finallykey.(*ecdsa.PublicKey), hash[:], signature)
		if verify == true {
			fmt.Printf("Signature successfully validated!\n\n")
			z = len(keys) - 1
		} else {
			fmt.Printf("\nSignature validation failed!\n\n")
			if z == len(keys)-2 {
				fmt.Printf("\nSignature validation failed! No keys remaining!\n\n")
				return false
			}
		}
		z++
	}
	return true
}

func ValidateECDSAIDassertion(token string, key []*ecdsa.PublicKey) bool {
	defer timeTrack(time.Now(), "Validateassertion")

	parts := strings.Split(token, ".")

	//  Verify recursively all lvls except most inner
	var i = 0
	var j = len(parts) - 1
	var k = len(key) - 1
	for i < len(parts)/2 && (i+1 < j-1) {
		// Extract first payload (parts[i]) and last signature (parts[j])
		clean := strings.Join(strings.Fields(strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")), ".")
		hash := hash256.Sum256([]byte(parts[i] + "." + clean))
		signature, err := base64.RawURLEncoding.DecodeString(parts[j])
		if err != nil {
			fmt.Printf("Error decoding signature: %s\n", err)
			return false
		}

		fmt.Printf("Claim     %d: %s\n", i, parts[i])
		fmt.Printf("Signature %d: %s\n", j, parts[j])

		link := Checkaudlink(parts[i], parts[i+1])
		if link == false {
			fmt.Printf("Iss/Aud link fails!")
			return false
		}
		fmt.Printf("Iss/Aud link successfully validated!")

		log.Printf("Verifying key number %d of %d", k, len(key)-1)
		verify := ecdsa.VerifyASN1(key[k], hash[:], signature)
		if verify == false {
			fmt.Printf("\nSignature validation failed!\n\n")
			return false
		}
		fmt.Printf("Signature %d successfully validated with key %d !\n\n", j, k)
		i++
		j--
		k--
	}

	// Verify Inner lvl

	// Verify if signature j is valid to parts[i] (there is no remaining previous assertion)
	hash := hash256.Sum256([]byte(parts[i]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[j])
	if err != nil {
		fmt.Printf("Error decoding signature: %s\n", err)
		return false
	}

	fmt.Printf("Claim     %d: %s\n", i, parts[i])
	fmt.Printf("Signature %d: %s\n", j, parts[j])

	log.Printf("Verifying key number %d of %d", k, len(key)-1)
	verify := ecdsa.VerifyASN1(key[k], hash[:], signature)
	if verify == false {
		fmt.Printf("\nSignature validation failed!\n\n")
		return false
	}
	fmt.Printf("Signature %d successfully validated with key %d !\n\n", j, k)

	return true
}

// generate a new schnorr signed encoded assertion
func NewSchnorrencode(claimset map[string]interface{}, oldmain string, key kyber.Scalar) (string, error) {
	defer timeTrack(time.Now(), "newencode")

	//  Marshall received claimset into JSON
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)

	// If no oldmain, generates a simple assertion...
	if oldmain == "" {
		tmpsig := Sign(payload, key)
		// fmt.Printf("Generated Signature: %s\n", tmpsig.String())

		sigbuf := bytes.Buffer{}
		if err := curve.Write(&sigbuf, &tmpsig); err != nil {
			fmt.Printf("Error in newschnorrencode! value: %s\n", err)
			return "", err
		}
		signature := base64.RawURLEncoding.EncodeToString(sigbuf.Bytes())

		encoded := strings.Join([]string{payload, signature}, ".")

		// debug
		// fmt.Printf("message size in base64 : %d\n", len(payload))
		// fmt.Printf("sig size in base64     : %d\n", len(signature))
		fmt.Printf("\nAssertion size         : %d\n", len(payload)+len(signature))

		return encoded, nil
	}

	//  ...otherwise, append assertion to previous content (oldmain) and sign all
	message := strings.Join([]string{payload, oldmain}, ".")
	tmpsig := Sign(message, key)
	// fmt.Printf("Generated Signature: %s\n", tmpsig.String())
	buf := bytes.Buffer{}
	if err := curve.Write(&buf, &tmpsig); err != nil {
		fmt.Printf("Error in append newschnorrencode! value: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(buf.Bytes())

	encoded := strings.Join([]string{message, signature}, ".")

	// debug
	// fmt.Printf("message size in base64 : %d\n", len(message))
	// fmt.Printf("sig size in base64     : %d\n", len(signature))
	fmt.Printf("\nAssertion size         : %d\n", len(message)+len(signature))

	return encoded, nil
}

// generate a new ecdsa signed encoded assertion
func NewECDSAencode(claimset map[string]interface{}, oldmain string, key crypto.Signer) (string, error) {
	defer timeTrack(time.Now(), "newencode")

	//  Marshall received claimset into JSON
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)

	// If no oldmain, generates a simple assertion
	if oldmain == "" {
		hash := hash256.Sum256([]byte(payload))
		s, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
		if err != nil {
			fmt.Printf("Error signing: %s\n", err)
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(s)
		encoded := strings.Join([]string{payload, sig}, ".")

		fmt.Printf("\nAssertion size: %d\n", len(payload)+len(sig))

		return encoded, nil
	}

	//  Otherwise, append assertion to previous content (oldmain) and sign it
	hash := hash256.Sum256([]byte(payload + "." + oldmain))
	s, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		fmt.Printf("Error signing: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{payload, oldmain, signature}, ".")

	fmt.Printf("\nAssertion size: %d\n", len(payload)+len(oldmain)+len(signature))

	return encoded, nil
}

// validateschnorrtrace include iss/aud link validation
func Validateschnorrtrace(token string) bool {
	defer timeTrack(time.Now(), "Validateassertion")

	parts := strings.Split(token, ".")

	//  Verify recursively all lvls except most inner
	var i = 0
	var j = len(parts) - 1
	for i < len(parts)/2 && (i+1 < j-1) {
		// Extract first payload (parts[i]) and last signature (parts[j])
		clean := strings.Join(strings.Fields(strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")), ".")
		message := strings.Join([]string{parts[i], clean}, ".")

		// Load kyber.Signature from token
		signature, _ := String2schsig(parts[j])

		// verify aud/iss link
		link := Checkaudlink(parts[i], parts[i+1])
		if link == false {
			return false
		}

		// extract publickey (kyber.Point) from issuer claim
		pubkey := Issuer2schpubkey(parts[i])
		fmt.Printf("Retrieved PublicKey from token: %s\n", pubkey.String())

		fmt.Printf("Signature verification: %t\n\n", Verify(message, signature, pubkey))
		i++
		j--
	}

	// Verify Inner lvl
	message := parts[i]

	// Load kyber.Signature from token
	signature, _ := String2schsig(parts[j])

	// extract publickey (kyber.Point) from issuer claim
	pubkey := Issuer2schpubkey(parts[i])
	fmt.Printf("Retrieved PublicKey from token: %s\n", pubkey.String())

	// Verify signature using extracted public key
	sigresult := Verify(message, signature, pubkey)

	fmt.Printf("Signature verification: %t\n\n", sigresult)
	return sigresult
}

// Function to perform schnorr token validation from out level to inside (last -> first assertion)
// This function did not check iss/aud link
func Validateschnorrassertion(token string) bool {
	defer timeTrack(time.Now(), "Validateassertion")

	parts := strings.Split(token, ".")

	//  Verify recursively all lvls except most inner
	var i = 0
	var j = len(parts) - 1
	for i < len(parts)/2 && (i+1 < j-1) {
		// Extract first payload (parts[i]) and last signature (parts[j])
		clean := strings.Join(strings.Fields(strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")), ".")
		message := strings.Join([]string{parts[i], clean}, ".")

		// Load kyber.Signature from token
		signature, _ := String2schsig(parts[j])
		fmt.Printf("Retrieved signature from token: %s\n", parts[j])

		// extract publickey (kyber.Point) from issuer claim
		pubkey := Issuer2schpubkey(parts[i])
		fmt.Printf("Retrieved PublicKey from token: %s\n", pubkey.String())

		fmt.Printf("Signature verification: %t\n\n", Verify(message, signature, pubkey))
		i++
		j--
	}

	// Verify Inner lvl
	message := parts[i]

	// Load kyber.Signature from token
	signature, _ := String2schsig(parts[j])
	fmt.Printf("Retrieved signature from token: %s\n", parts[j])

	// extract publickey (kyber.Point) from issuer claim
	pubkey := Issuer2schpubkey(parts[i])
	fmt.Printf("Retrieved PublicKey from token: %s\n", pubkey.String())

	// Verify signature using extracted public key
	sigresult := Verify(message, signature, pubkey)

	fmt.Printf("Signature verification: %t\n\n", sigresult)
	return sigresult
}

// Collect necessary data to perform Galindo-Garcia validation to 'n' parts
func Validategg(token string) bool {
	defer timeTrack(time.Now(), "Galindo-Garcia Validation")

	// split received token
	parts := strings.Split(token, ".")

	var i = 0
	var j = len(parts) - 1
	fmt.Printf("Number of keys			: %d\n", len(parts)/2)
	var setpubkey []kyber.Point
	var setSigR []kyber.Point
	var setH []kyber.Scalar

	// go through all token parts collecting and constructing necessary data
	for i < len(parts)/2 && (i+1 < j-1) {

		// Construct message
		clean := strings.Join(strings.Fields(strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")), ".")
		message := strings.Join([]string{parts[i], clean}, ".")

		// Load kyber.Signature
		signature, err := String2schsig(parts[j])
		if err != nil {
			// Load kyber.Point
			// fmt.Printf("Fail loading signature! Value		:  %s\n",  err)
			// fmt.Printf("Trying compact mode.\n")
			kyPoint, err := String2point(parts[j])
			if err != nil {
				fmt.Println("Error converting string to point!")
				return false
			}
			setSigR = append(setSigR, kyPoint)
			fmt.Printf("Retrieved signature from token: %s\n", parts[j])
		} else {
			// extract and store signature.R
			setSigR = append(setSigR, signature.R)
			fmt.Printf("Retrieved signature from token: %s\n", parts[j])
		}

		// Load issuer PublicKey
		pubkey := Issuer2schpubkey(parts[i])
		setpubkey = append(setpubkey, pubkey)
		fmt.Printf("Retrieved PublicKey from token: %s\n\n", setpubkey[i].String())

		// calculate and store hash
		setH = append(setH, Hash(setSigR[i].String()+message+pubkey.String()))
		// fmt.Printf("Hash[%d]							: %s\n\n", setH[i].String())

		i++
		j--
	}

	// Collect Inner lvl
	message := parts[i]

	// Load kyber.Signature
	signature, err := String2schsig(parts[j])
	if err != nil {
		// Load kyber.Point
		// fmt.Printf("Fail loading signature! Value		: %s\n",  err)
		// fmt.Printf("Trying compact mode.\n")
		kyPoint, err := String2point(parts[j])
		if err != nil {
			fmt.Println("Error converting string to point!")
			return false
		}
		setSigR = append(setSigR, kyPoint)
		fmt.Printf("Retrieved signature from token: %s\n", parts[j])
	} else {
		// extract and store signature.R
		setSigR = append(setSigR, signature.R)
		fmt.Printf("Retrieved signature from token: %s\n", parts[j])
	}

	// Load first original PublicKey
	pubkey := Issuer2schpubkey(parts[i])
	setpubkey = append(setpubkey, pubkey)
	fmt.Printf("Retrieved PublicKey from token: %s\n\n", setpubkey[i].String())

	// calc hash
	setH = append(setH, Hash(setSigR[i].String()+message+pubkey.String()))
	// fmt.Printf("Hash[%d]              					: %s\n", setH[i].String())

	// collect last signature.S
	lastsigS, err := String2schsig(parts[len(parts)-1])
	if err != nil {
		fmt.Println("Error converting string to schnorr signature!")
		return false
	}
	// fmt.Printf("\nLastsig.S             					: %s\n",  lastsigS.S.String())

	sigver := Verifygg(pubkey, setSigR, setH, lastsigS.S)
	fmt.Println("Signature verification: ", sigver)

	return sigver
}

// Convert a schnorr public key to string
func Schpubkey2string(publicKey kyber.Point) string {
	buf := bytes.Buffer{}
	if err := curve.Write(&buf, &publicKey); err != nil {
		fmt.Printf("Error in pubkey2string! value: %s\n", err)
		os.Exit(1)
	}
	result := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	return result
}

// Convert a kyber.point to string
func Point2string(sourcepoint kyber.Point) (string, error) {
	buf := bytes.Buffer{}
	if err := curve.Write(&buf, &sourcepoint); err != nil {
		fmt.Printf("Error in point2string! value: %s\n", err)
		return "", err
	}
	result := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	return result, nil
}

// Convert a string to kyber.point
func String2point(message string) (kyber.Point, error) {
	var point kyber.Point

	tmppt, err := base64.RawURLEncoding.DecodeString(message)
	if err != nil {
		fmt.Printf("Error decoding point string: %s\n", err)
		return point, err
	}
	// fmt.Printf("message value: %s\n",  decodedparti)
	buf := bytes.NewBuffer(tmppt)
	if err := curve.Read(buf, &point); err != nil {
		fmt.Printf("Error in string2point! value: %s\n", err)
		return point, err
	}

	return point, nil
}

// Convert issuer claim to kyber.point
func Issuer2schpubkey(message string) kyber.Point {

	// Decode from b64 and retrieve issuer claim (public key)
	decodedparti, _ := base64.RawURLEncoding.DecodeString(message)
	tmppubkey, _ := base64.RawURLEncoding.DecodeString(fmt.Sprintf("%s", ExtractValue(string(decodedparti), "iss")))

	// Convert claim to curve point
	var pubkey kyber.Point
	buf := bytes.NewBuffer(tmppubkey)
	if err := curve.Read(buf, &pubkey); err != nil {
		fmt.Printf("Error in  Issuer2schpubkey! value: %s\n", err)
		os.Exit(1)
	}

	return pubkey
}

// Convert a schnorr signature to string
func Schsig2string(signature Signature) string {
	buf := bytes.Buffer{}
	if err := curve.Write(&buf, &signature); err != nil {
		fmt.Printf("Error in signature2string! value: %s\n", err)
		os.Exit(1)
	}
	result := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	return result
}

// Convert a string to schnorr signature
func String2schsig(message string) (Signature, error) {
	var signature Signature

	tmpsig, err := base64.RawURLEncoding.DecodeString(message)
	if err != nil {
		fmt.Printf("Error decoding signature: %s\n", err)
		return signature, err
	}
	// fmt.Printf("message value: %s\n",  decodedparti)
	buf := bytes.NewBuffer(tmpsig)
	if err := curve.Read(buf, &signature); err != nil {
		// fmt.Printf("Error reading string to signature: %s\n",  err)
		return signature, err
	}

	return signature, nil
}

// verify if aud==iss
func Checkaudlink(issmsg string, audmsg string) bool {

	// Decode issmsg from b64 and retrieve issuer claim
	decodediss, _ := base64.RawURLEncoding.DecodeString(issmsg)
	tmpiss := ExtractValue(string(decodediss), "iss")

	// Decode audmsg from b64 and retrieve audience claim
	decodedaud, _ := base64.RawURLEncoding.DecodeString(audmsg)
	tmpaud := ExtractValue(string(decodedaud), "aud")

	// check if iss == aud
	if tmpiss != tmpaud {
		fmt.Printf("\nIssuer/Audience link fails!\n")
		return false
	}
	fmt.Printf("\nIssuer/Audience link validated!\n")
	return true
}

// Retrieve key in kid claim from local Key server (PoC function)
func getkeys(message string) ([]string, error) {

	decclaim, _ := base64.RawURLEncoding.DecodeString(message)
	kid := ExtractValue(string(decclaim), "kid")
	fmt.Printf("Search kid: %s\n", kid)

	url := "http://localhost:8888/key/" + fmt.Sprintf("%s", kid)
	fmt.Printf("\nKey Server URL: %s\n", url)

	var jsonStr = []byte(fmt.Sprintf("%s", kid))
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonStr))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("error: %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Errorf("error: %s", err)
		return nil, err
	}

	keys := strings.SplitAfter(fmt.Sprintf("%s", string(body)), "}")
	fmt.Printf("Number of Keys received from IdP: %d\n\n", len(keys)-1)
	if len(keys)-1 == 0 {
		fmt.Printf("\nError: No keys received!\n\n")
		return nil, err
	}

	return keys, nil

}

// Add a key in local Key server (PoC function)
func Addkey(key string) (string, error) {

	// url := "http://"+filesrv+":"+filesrvport+"/addkey"
	url := "http://localhost:8888/addkey"
	fmt.Printf("\nKey Server URL: %s\n", url)

	var jsonStr = []byte(key)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("X-Custom-Header", "keydata")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("error: %s", err)
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	return string(body), nil
}

// Parse an ECDSA public key
func ParseECDSAPublicKey(pubPEM string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	// switch pub := pub.(type) {
	// case *rsa.PublicKey:
	// 	fmt.Println("pub is of type RSA:", pub)
	// // case *dsa.PublicKey:
	// // 	fmt.Println("pub is of type DSA:", pub)
	// case *ecdsa.PublicKey:
	// 	fmt.Println("pub is of type ECDSA:", pub)
	// // case ed25519.PublicKey:
	// // 	fmt.Println("pub is of type Ed25519:", pub)
	// default:
	// 	panic("unknown type of public key")
	// }

	return pub, nil

}

// EncodeECDSAPublicKey encodes an *ecdsa.PublicKey to PEM format.
//
//	TODO: FIX type, that should be different based on input key type
//
// At this time it only support ECDSA
func EncodeECDSAPublicKey(key *ecdsa.PublicKey) ([]byte, error) {

	derKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	keyBlock := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: derKey,
	}

	return pem.EncodeToMemory(keyBlock), nil
}

// Print content of an encoded assertion
func PrintAssertion(assertion string) {

	// Split received token
	parts := strings.Split(assertion, ".")
	fmt.Println("Total parts: ", len(parts))
	if len(parts) < 2 {
		fmt.Printf("Invalid number of parts!")
		os.Exit(1)
	}

	// print single assertion
	if len(parts) < 3 {
		dectmp, _ := base64.RawURLEncoding.DecodeString(parts[0])
		fmt.Printf("Claim     [%d]	: %s\n", 0, dectmp)
		fmt.Printf("Signature [%d]	: %s\n", 1, parts[1])
		os.Exit(1)
	}

	// print token claims
	var i = 0
	for i < len(parts)/2 {
		dectmp, _ := base64.RawURLEncoding.DecodeString(parts[i])
		fmt.Printf("Claim     [%d]	: %s\n", i, dectmp)
		i++
	}

	// print token  signatures
	j := len(parts) / 2
	for j < len(parts) {
		fmt.Printf("Signature [%d]	: %s\n", j, parts[j])
		j++
	}

}

// generate a new Dilithium signed encoded assertion
func NewDilithiumencode(claimset map[string]interface{}, oldmain string) (string, error) {
	defer timeTrack(time.Now(), "NewDilithiumencode")

	//Creates a Dilithium instance with recommended security level
	mode := dilithium.Mode3
	// Generates a keypair.
	pk, sk, err := mode.GenerateKey(nil)
	if err != nil {
		log.Printf("Error signing: %s\n", err)
		return "", err
	}
	// // Packs public and private key
	// packedSk := sk.Bytes()
	// packedPk := pk.Bytes()

	// // Load it again
	// sk2 := mode.PrivateKeyFromBytes(packedSk)
	// pk2 := mode.PublicKeyFromBytes(packedPk)

	//  Marshall received claimset into JSON
	// dilikey 			:= base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprint(pk2)))
	// claimset["dilikey"] = dilikey
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)

	// If no oldmain, generates a simple assertion
	if oldmain == "" {
		hash := hash256.Sum256([]byte(payload))
		s := mode.Sign(sk, hash[:])
		if s == nil {
			log.Printf("Error signing!\n")
			return "", err
		}
		// Checks whether a signature is correct
		// Here just to test. In PoC maybe interesting remove the verification from signature function, reducing execution time.
		if !mode.Verify(pk, hash[:], s) {
			panic("incorrect signature")
		} else {
			log.Printf("Dilithium signature verification successful!\n")
		}

		sig := base64.RawURLEncoding.EncodeToString(s)
		encoded := strings.Join([]string{payload, sig}, ".")

		log.Printf("\nAssertion size: %d\n", len(payload)+len(sig))

		return encoded, nil
	}

	//  Otherwise, append assertion to previous content (oldmain) and sign it
	hash := hash256.Sum256([]byte(payload + "." + oldmain))
	s := mode.Sign(sk, hash[:])
	if s == nil {
		log.Printf("Error signing!\n")
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{payload, oldmain, signature}, ".")

	fmt.Printf("\nAssertion size: %d\n", len(payload)+len(oldmain)+len(signature))

	return encoded, nil
}

func Pubkey2evp(pubkey JWK) (*C.EVP_PKEY, error) {

	if pubkey.Kty != "RSA" {
		log.Printf("invalid key type:", pubkey.Kty)
		return nil, fmt.Errorf("Unsuported key type")
	}

	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(pubkey.N)
	if err != nil {
		log.Printf(fmt.Sprintf("Error encoding n: %s", err))
		return nil, err		
	}
	e := 0

	// The default exponent is usually 65537, so just compare the
	// base64 for [1,0,1] or [0,1,0,1]
	if pubkey.E == "AQAB" || pubkey.E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		log.Printf("need to decode e:", pubkey.E)
	}

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}

	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		log.Printf(fmt.Sprintf("Error marshalling PKIX public key: %s", err))
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	var out bytes.Buffer
	pem.Encode(&out, block)
	fmt.Println("Generated public key in PEM format: ", out.String())

	// Create output file
	file, err := os.Create(os.Getenv("PEM_PATH"))
	if err != nil {
		log.Printf("Error creating output file: %s", err)
		return nil, err
	}

	log.Printf("Writing PEM file...")
	_, err = file.Write(out.Bytes())
	if err != nil {
		log.Printf("Error writing PEM file: ", err)
		return nil, err
	}
	file.Close()

	// Open OAuth PEM file containing Public Key
	var filepem *C.FILE
	filepem = C.fopen((C.CString)(os.Getenv("PEM_PATH")), (C.CString)("r"))
	if filepem == nil {
		log.Printf("Error opening PEM file!")
		return nil, err
	}

	// Load key from PEM file to VKEY
	var vkey *C.EVP_PKEY
	vkey = nil
	C.PEM_read_PUBKEY(filepem, &vkey, nil, nil)

	C.fclose(filepem)

	return vkey, nil

}

package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net"
	"fmt"
	"os"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"crypto/sha256"
	"crypto/rand"
	"time"
	"crypto/rsa"
	"crypto/ecdsa"
	"math/big"
	"strings"
	"strconv"
	"bytes"	
	"crypto/x509"
	"encoding/pem"
	// "unsafe"
	
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

const (
	// Workload API socket path
	socketPath	= "unix:///tmp/spire-agent/public/api.sock"
)

type keydata struct {
	Kid			string `json:kid",omitempty"`
	Alg			string `json:alg",omitempty"`
	Pkey		[]byte `json:pkey",omitempty"`
	Exp			int64  `json:exp",omitempty"`
}

func GetOutboundIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP
}

func main() {
	var curve = edwards25519.NewBlakeSHA256Ed25519()

// Usage: ./client <operation> <parameter>
// 
// Supported Operations: mint, keys, validate
// Parameters: mint requires Oauth Token. Validate requires DASVID to be validated.

// example:
// ./client mint <OAUTH TOKEN>

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var endpoint string
	
	// Retrieve local IP
	// In this PoC example, client and server are running in the same host, so serverIP = clientIP 
	Iplocal := GetOutboundIP()
	StrIPlocal := fmt.Sprintf("%v", Iplocal)
	serverURL := StrIPlocal + ":8443"

	operation := os.Args[1]

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString("example.org")

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	switch operation {

	case "help":
		fmt.Printf(`
		
Description:
 Client to interact with SPIRE and Asserting WL, also useful to mint assertions. 
 Developed to assertions and tokens demo.

Main functions:

  - next
      Add next hop assertion to existing token 
	  usage: ./assertgen next <next_hop_ID> <originaltoken> <spiffeid/svid> 
  - generic
      Generate a new assertion
	  usage: ./assertgen generic <assertionkey> <assertion_value> <spiffeid/svid>
  - append
      Append assertion to an existing token
	  usage: ./assertgen append <originaltoken> <assertionkey> <assertion_value> <spiffeid/svid>

  - print
      Print informed nest token
      usage: ./main printnest token

`)
	os.Exit(1)
// - mint
// Ask for a new minted DASVID
// usage: ./assertgen mint <OAuthtoken>
// - keys
// Ask for Asserting Workload Public Key  
// usage: ./assertgen keys
// - validate
// Ask for DASVID signature/expiration validation
// usage: ./assertgen validate <dasvidtoken>
// - introspect
// Ask for ZKP from informed DASVID
// usage: ./assertgen introspect <dasvidtoken>

	case "print":
		// 	Print informed nest token
		//  usage: ./main printnest token
		token := os.Args[2]
		printtoken(token)
		os.Exit(1)
	
    case "mint":
		// 	Ask for a new minted DASVID
		//  usage: ./assertgen mint OAuthtoken
		token := os.Args[2]
		endpoint = "https://"+serverURL+"/mint?AccessToken="+token

    case "keys":
		// 	Ask for Asserting Workload Public Key
		//  usage: ./assertgen keys
		endpoint = "https://"+serverURL+"/keys"

    case "validate":
		// 	Ask for DASVID signature/expiration validation
		//  usage: ./assertgen validate DASVID
		dasvid := os.Args[2]
		endpoint = "https://"+serverURL+"/validate?DASVID="+dasvid

	case "introspect":
		// 	Ask for ZKP from informed DASVID
		//  usage: ./assertgen introspect DASVID
		dasvid := os.Args[2]
		endpoint = "https://"+serverURL+"/introspect?DASVID="+dasvid
		
	case "next":
		// 	Add next hop assertion to existing DASVID 
		//  usage: ./assertgen next next_hop_ID DASVID spiffeid/svid

		// Fetch claims data
		clientSVID := dasvid.FetchX509SVID()
		clientID := clientSVID.ID.String()
		clientkey := clientSVID.PrivateKey

		issue_time := time.Now().Round(0).Unix()

		// nxt being passed as argument. in poc it is retrieved from mTLS connection
		next := os.Args[2]
		maintoken := os.Args[3]
		
		svidAsIssuer := os.Args[4]

		//  Define issuer type:
		var issuer string
		switch svidAsIssuer {
			case "spiffeid":
				// Uses SPIFFE-ID as ISSUER
				issuer = clientID
			case "svid":
				// Uses SVID cert bundle as ISSUER
				tmp, _, err := clientSVID.Marshal()
				if err != nil {
					fmt.Println("Error retrieving SVID: ", err)
					os.Exit(1)
				}
				issuer = fmt.Sprintf("%v", tmp)
			default:
				fmt.Println("Error defining issuer! Select spiffeid or svid.")
				os.Exit(1)
		}
		
		tokenclaims := map[string]interface{}{
			"iss":		issuer,
			"iat":	 	issue_time,
			"aud":		next,
			"alg":		"ES256",
		}
		assertion, err := newencode(tokenclaims, maintoken, clientkey)
		if err != nil {
			fmt.Println("Error generating signed assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		os.Exit(1)
	
	case "generic":
		// Generate a new assertion
		// usage: ./main generic assertionKey assertionValue spiffeid/svid

		// Fetch claims data
		clientSVID 		:= dasvid.FetchX509SVID()
		clientID 		:= clientSVID.ID.String()
		clientkey 		:= clientSVID.PrivateKey

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// assertion key:value
		assertionkey 	:= os.Args[2]
		assertionvalue 	:= os.Args[3]

		// uses spiffeid or svid as issuer
		svidAsIssuer 	:= os.Args[4]

		// generate encoded key
		pubkey := clientkey.Public().(*ecdsa.PublicKey)
		encKey, _ := EncodePublicKey(pubkey)

		//  Define issuer type:
		var issuer string
		switch svidAsIssuer {
		case "spiffeid":
			// Uses SPIFFE-ID as ISSUER
			issuer = clientID
		case "svid":
			// Uses SVID cert bundle as ISSUER
			tmp, _, err := clientSVID.Marshal()
			if err != nil {
				fmt.Println("Error retrieving SVID: ", err)
				os.Exit(1)
			}
			issuer = fmt.Sprintf("%s", tmp)
		case "anonymous":
			// Uses public key as ISSUER
			issuer = fmt.Sprintf("%s", encKey)

		default:
			fmt.Println("Error defining issuer! Select spiffeid or svid.")
			os.Exit(1)
	}
		
		// Define assertion claims
		kid 			:= base64.RawURLEncoding.EncodeToString([]byte(clientID))
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"iat"		:	 	issue_time,
			"kid"		:		kid,
			assertionkey:		assertionvalue,
		}
		assertion, err := newencode(assertionclaims, "", clientkey)
		if err != nil {
			fmt.Println("Error generating signed assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))

		//  save public key in IdP
		key := &keydata{
			Kid		:	kid,
			Alg		:	"EC256",
			Pkey	:	encKey,
			Exp		:	time.Now().Add(time.Hour * 1).Round(0).Unix(),
		}
		mkey, _ := json.Marshal(key)
		savekey, err := addkey(fmt.Sprintf("%s",mkey))
		if err != nil {
			fmt.Errorf("error: %s", err)
			os.Exit(1)
		}
		fmt.Println("Key successfully stored: ", savekey)


		os.Exit(1)

	case "schnorr":
		// Generate a new assertion with schnorr signature
		// usage: ./main schnorr assertionKey assertionValue

		// Generate Keypair
		
		privateKey := curve.Scalar().Pick(curve.RandomStream())
    	// publicKey := curve.Point().Mul(privateKey, curve.Point().Base())

		// Issuer
		// issuer 	:= base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s", publicKey)))

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// assertion key:value
		assertionkey 	:= os.Args[2]
		assertionvalue 	:= os.Args[3]
		assertionclaims := map[string]interface{}{
			// OBS: como no schnorr dá pra derivar a public key da msg + assinatura, talvez possamos remover o issuer no anonymous mode, sem maiores impactos
			// "iss"		:		issuer,
			"iat"		:	 	issue_time,
			assertionkey:		assertionvalue,
		}
		assertion, err := newschnorrencode(assertionclaims, "", privateKey)
		if err != nil {
			fmt.Println("Error generating signed schnorr assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))

		os.Exit(1)

	case "sizes":
		// test sizes of received token and nested mains
		// usage: ./main test nestedtoken

		inputtoken	:=	os.Args[2]
		fmt.Println("inputtoken: ", inputtoken)
		
		// var tmptoken string
		// tmptoken = inputtoken
		tokenclaims := dasvid.ParseTokenClaims(inputtoken)

		var mainvalue string
		mainvalue = inputtoken
		// Go deeper in the token if main exists
		for tokenclaims["main"] != nil {

			mainvalue = strings.Trim(fmt.Sprintf("%s", tokenclaims["main"]), "[]")
			mainparts := strings.Split(mainvalue, " ")
			mainvalue =  strings.Join([]string{mainparts[0], mainparts[1], mainparts[2]}, ".")

			// collect parts size
			header := strconv.Itoa(len(mainparts[0]))
			payload := strconv.Itoa(len(mainparts[1]))
			signature := strconv.Itoa(len(mainparts[2]))
		
			tmpresults := []string{header, payload, signature}
			results := strings.Join(tmpresults, "-")

			// If the file doesn't exist, create it, or append to the file
			file, err := os.OpenFile("./sizes.test", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Writing to file...")
			json.NewEncoder(file).Encode(results)
			if err := file.Close(); err != nil {
				log.Fatal(err)
			}

			if tokenclaims["main"] != "" {
				fmt.Println("mainvalue", mainvalue)
				tokenclaims = dasvid.ParseTokenClaims(mainvalue)	
			}

		}

		tmpparts := strings.Split(mainvalue, ".")
		// collect last level
		header := strconv.Itoa(len(tmpparts[0]))
		payload := strconv.Itoa(len(tmpparts[1]))
		signature := strconv.Itoa(len(tmpparts[2]))
		tmpresults := []string{header, payload, signature}
		results := strings.Join(tmpresults, "-")

		// // save everything in file
		// // If the file doesn't exist, create it, or append to the file
		file, err := os.OpenFile("./sizes.test", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Writing to file...")
		json.NewEncoder(file).Encode(results)
		if err := file.Close(); err != nil {
			log.Fatal(err)
		}
		os.Exit(1)
	
	case "append":
		// Append assertion to an existing token
		//  usage: ./assertgen append originaltoken assertionKey assertionValue spiffeid/svid
		// Changed "alg" to "kid", that is used to retrieve correct key informations from IdP 
		// kid = public key hash

		// Fetch claims data
		clientSVID 		:= dasvid.FetchX509SVID()
		clientID 		:= clientSVID.ID.String()
		clientkey 		:= clientSVID.PrivateKey

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// main token and assertion values
		mainvalue	 	:= os.Args[2]
		assertionkey 	:= os.Args[3]
		assertionvalue 	:= os.Args[4]

		// uses spiffeid or svid as token/assertion issuer
		svidAsIssuer 	:= os.Args[5]

		// validate main token before appending
		pubkey 			:= clientkey.Public()
		encKey, _ := EncodePublicKey(pubkey.(*ecdsa.PublicKey))
		valid 			:= validateassertion(mainvalue)
		if valid != true{
			fmt.Println("Cannot append: Invalid assertion!")
			os.Exit(1)
		}

		//  Define issuer type:
		var issuer string
		switch svidAsIssuer {
			case "spiffeid":
				// Uses SPIFFE-ID as ISSUER
				issuer = clientID
			case "svid":
				// Uses SVID cert bundle as ISSUER
				tmp, _, err := clientSVID.Marshal()
				if err != nil {
					fmt.Println("Error retrieving SVID: ", err)
					os.Exit(1)
				}
				issuer = fmt.Sprintf("%s", tmp)
			case "anonymous":
				//Uses public key as ISSUER
				issuer = fmt.Sprintf("%s", encKey)

			default:
				fmt.Println("Error defining issuer! Select spiffeid or svid.")
				os.Exit(1)
		}

			// Define token claims
			fmt.Println("**mainvalue size: ", len(mainvalue))
			fmt.Println("Other claims size: ", len(issuer)+len(assertionvalue)+len(string(issue_time)))

			kid 			:= base64.RawURLEncoding.EncodeToString([]byte(clientID))
			tokenclaims 	:= map[string]interface{}{
				"iss"		:				issuer,
				"iat"		:	 			issue_time,
				"kid"		:				kid[:],
				assertionkey:		assertionvalue,
			}
			assertion, err := newencode(tokenclaims, mainvalue, clientkey)
			if err != nil {
				fmt.Println("Error generating signed assertion!")
				os.Exit(1)
			} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		fmt.Println("Assertion size", len(assertion))

		//  save public key in IdP
		key := &keydata{
			Kid		:	kid[:],
			Alg		:	"EC256",
			Pkey	:	encKey,
			Exp		:	time.Now().Add(time.Hour * 1).Round(0).Unix(),
		}
		mkey, _ := json.Marshal(key)
		savekey, err := addkey(fmt.Sprintf("%s",mkey))
		if err != nil {
			fmt.Errorf("error: %s", err)
			os.Exit(1)
		}
		fmt.Println("Key successfully stored: ", savekey)

		os.Exit(1)

	case "multiappend":
		defer timeTrack(time.Now(), "multiappend ")
		// Append assertion to an existing token
		//  usage: ./main multiappend originaltoken assertionKey assertionValue howmany spiffeid/svid

		// main token and assertion values
		mainvalue	 		:= os.Args[2]
		assertionkey 		:= os.Args[3]
		assertionvalue 		:= os.Args[4]
		manytimes, _	 	:= strconv.Atoi(os.Args[5])

		// uses spiffeid or svid as token/assertion issuer
		svidAsIssuer 	:= os.Args[6]

		i := 0 
		for i <  manytimes {

			// timestamp
			issue_time 		:= time.Now().Round(0).Unix()

			// generate encoded public key
			clientSVID 		:= dasvid.FetchX509SVID()
			clientID 		:= clientSVID.ID.String()
			clientkey 		:= clientSVID.PrivateKey
			pubkey		:= clientkey.Public().(*ecdsa.PublicKey)
			encKey, _ 	:= EncodePublicKey(pubkey)

			//  Define issuer type:
			var issuer string
			switch svidAsIssuer {
				case "spiffeid":
					// Uses SPIFFE-ID as ISSUER
					issuer = clientID
					// fmt.Println("issuer: ", issuer)
				case "svid":
					// Uses SVID cert bundle as ISSUER
					tmp, _, err := clientSVID.Marshal()
					if err != nil {
						fmt.Println("Error retrieving SVID: ", err)
						os.Exit(1)
					}
					issuer = fmt.Sprintf("%s", tmp)
				case "anonymous":
					// Uses public key as ISSUER
					issuer = fmt.Sprintf("%s", encKey)
					
				default:
					fmt.Println("Error defining issuer! Select spiffeid or svid.")
					os.Exit(1)
			}
			
			// Define token claims
			kid 			:= base64.RawURLEncoding.EncodeToString([]byte(clientID))
			tokenclaims 	:= 	map[string]interface{}{
				"iss"		:	issuer,
				"iat"		:	issue_time,
				"kid"		:	kid[:],
				assertionkey+fmt.Sprintf("%v", i):	assertionvalue+fmt.Sprintf("%v", i),
			}
			assertion, err := newencode(tokenclaims, mainvalue, clientkey)
			if err != nil {
				fmt.Println("Error generating signed assertion!")
				os.Exit(1)
			} 

			mainvalue = fmt.Sprintf("%s", assertion)
			fmt.Printf("Resulting assertion: %s\n", mainvalue)

			//  save public key in IdP
			key := &keydata{
				Kid		:	kid[:],
				Alg		:	"EC256",
				Pkey	:	encKey,
				Exp		:	time.Now().Add(time.Hour * 1).Round(0).Unix(),
			}
			mkey, _ := json.Marshal(key)
			savekey, err := addkey(fmt.Sprintf("%s",mkey))
			if err != nil {
				fmt.Errorf("error: %s", err)
				os.Exit(1)
			}
			fmt.Println("Key successfully stored: ", savekey)
			i++
		}

		os.Exit(1)
	case "verify":
		// 	Verify assertion signature
		//  usage: ./assertgen verify direction assertion
		//  extract the keyid from token and use it to retrieve public key from IdP
		// 
		// clientSVID 		:= dasvid.FetchX509SVID()
		// clientkey 		:= clientSVID.PrivateKey
		// pubkey 			:= clientkey.Public()

		// direction := os.Args[2]
		assertion := os.Args[2]

		// if (direction=="reverse") {
		// 	validatreverse(assertion, pubkey.(*ecdsa.PublicKey))
		// }
		// if (direction=="direct") {
			validateassertion(assertion)
		// }
		os.Exit(1)
	case "ver_schnorr":
		// 	Verify assertion schnorr signature
		//  usage: ./assertgen ver_schnorr assertion 
		// 

		fmt.Printf("*** Schnorr Signature validation! ***\n")
		assertion := os.Args[2]
		parts := strings.Split(assertion, ".")
		// message, _ 	:= base64.RawURLEncoding.DecodeString(parts[0]) 
		tmpsig, _ 	:= base64.RawURLEncoding.DecodeString(parts[1])
		var signature dasvid.Signature
		buf := bytes.NewBuffer(tmpsig)
		if err := curve.Read(buf, &signature); err != nil {
			fmt.Printf("Error! value: %s\n",  err)
			os.Exit(1)
		}

		fmt.Printf("Received signature: %s\n", signature)

		derivedPublicKey := dasvid.PublicKey(parts[0], signature)
		fmt.Printf("derived PublicKey: %s\n", derivedPublicKey)

    	fmt.Printf("Checking signature %t\n\n", dasvid.Verify(parts[0], signature, derivedPublicKey))

		os.Exit(1)	
	
	}

	r, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", serverURL, err)
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	fmt.Printf("%s", body)
}



// jwkEncode encodes public part of an RSA or ECDSA key into a JWK.
// The result is also suitable for creating a JWK thumbprint.
// https://tools.ietf.org/html/rfc7517
func jwkEncode(pub crypto.PublicKey) (string, error) {
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

func newencode(claimset map[string]interface{}, oldmain string, key crypto.Signer) (string, error) {
	defer timeTrack(time.Now(), "newencode")

	//  Marshall received claimset into JSON
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)

	// If no oldmain, generates a simple assertion
	if oldmain == "" {
		hash 	:= sha256.Sum256([]byte(payload))
		s, err 	:= ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
		if err 	!= nil {
			fmt.Printf("Error signing: %s\n", err)
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(s)
		encoded := strings.Join([]string{payload, sig}, ".")

		// debug
		// fmt.Printf("payload size in base64  : %d\n", len(payload))
		// fmt.Printf("sig size in base64      : %d\n", len(sig))
		fmt.Printf("Assertion size: %d\n", len(payload) + len(sig))

		return encoded, nil
	}
	
	//  Otherwise, append assertion to previous content (oldmain) and sign it
	hash	:= sha256.Sum256([]byte(payload + "." + oldmain))
	s, err 	:= ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		fmt.Printf("Error signing: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{payload, oldmain, signature}, ".")
	
	// debug
	// fmt.Printf("payload size in base64	: %d\n", len(payload))
	// fmt.Printf("oldpay size in base64	: %d\n", len(oldmain))
	// fmt.Printf("sig size in base64		: %d\n", len(signature))
	fmt.Printf("Assertion size: %d\n", len(payload) + len(oldmain)+ len(signature))

	return encoded, nil
}

// Function to perform token validation from out level to inside (last -> first assertion)
func validateassertion(token string) bool {
	defer timeTrack(time.Now(), "Validateassertion")

	parts := strings.Split(token, ".")

	//  Verify recursively all lvls except most inner
	var i = 0
	var j = len(parts)-1
	for (i < len(parts)/2 && (i+1 < j-1)) {
		// Extract first payload (parts[i]) and last signature (parts[j])
		clean 			:= strings.Join(strings.Fields(strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")), ".")
		hash 			:= sha256.Sum256([]byte(parts[i] + "." + clean))
		signature, err 	:= base64.RawURLEncoding.DecodeString(parts[j])
		if err != nil {
			fmt.Printf("Error decoding signature: %s\n", err)
			return false
		}

		// retrieve key from IdP
		decclaim, _ := base64.RawURLEncoding.DecodeString(parts[i])
		var tmpkey map[string]interface{}
		json.Unmarshal([]byte(decclaim), &tmpkey)
		kid := tmpkey["kid"]
		pkey, _ := getkey(fmt.Sprintf("%s", kid))
		// fmt.Printf("decclaim: %s\n", decclaim)
		fmt.Printf("Search kid: %s\n", kid)
		keys := strings.SplitAfter(fmt.Sprintf("%s", pkey), "}")
		fmt.Printf("Number of Keys received from IdP: %d\n\n", len(keys)-1)
		if (len(keys)-1 == 0){
			fmt.Printf("\nError: No keys received!\n\n")
			return false
		}

		// Debug
		// fmt.Printf("Retrieved Keys from IdP: %s\n", pkey)
		// fmt.Printf("keys: %s\n", keys)
		// fmt.Printf("keys[0]: %q\n", keys[0])
		// fmt.Printf("cleankeys: %s\n", cleankeys)
		// fmt.Printf("Splitted string: %q\n", cleankeys)
		fmt.Printf("Claim     %d: %s\n", i, parts[i])
		fmt.Printf("Signature %d: %s\n", j, parts[j])

		// Search for a valid key
		var z = 0
		for (z < len(keys)-1) {
			cleankeys 		:= strings.Trim(fmt.Sprintf("%s", keys[z]), "\\")
			
			var tmpkey map[string]interface{}
			json.Unmarshal([]byte(cleankeys), &tmpkey)
			pkey, _ 		:= base64.RawURLEncoding.DecodeString(fmt.Sprintf("%s", tmpkey["Pkey"]))
			finallykey, _ 	:= ParseECPublicKey(fmt.Sprintf("%s", pkey))

			verify 			:= ecdsa.VerifyASN1(finallykey.(*ecdsa.PublicKey), hash[:], signature)
			if (verify == true){
				fmt.Printf("Signature successfully validated!\n\n")
				z = len(keys)-1
			} else {
				fmt.Printf("\nSignature validation failed!\n\n")
				if (z == len(keys)-2) {
					fmt.Printf("\nSignature validation failed! No keys remaining!\n\n")
					return false
				}
			}
			z++
			// Debug
			// fmt.Printf("Received Keys: %s\n", cleankeys)
			// fmt.Printf("pkey: %s\n", pkey)
			// fmt.Printf("finallykey: %s\n", finallykey)
		}
		i++
		j--
	}

	// Verify Inner lvl

	// Verify if signature j is valid to parts[i] (there is no remaining previous assertion)
	hash 			:= sha256.Sum256([]byte(parts[i]))
	signature, err 	:= base64.RawURLEncoding.DecodeString(parts[j])
	if (err != nil){
		fmt.Printf("Error decoding signature: %s\n", err)
		return false
	}

	// retrieve key from IdP
	decclaim, _ := base64.RawURLEncoding.DecodeString(parts[i])
	var tmpkey map[string]interface{}
	json.Unmarshal([]byte(decclaim), &tmpkey)
	kid := tmpkey["kid"]
	pkey, _ := getkey(fmt.Sprintf("%s", kid))
	fmt.Printf("Search kid: %s\n", kid)
	keys := strings.SplitAfter(fmt.Sprintf("%s", pkey), "}")
	fmt.Printf("Number of Keys received from IdP: %d\n\n", len(keys)-1)

	// fmt.Printf("Received Keys: %s\n", keys)
	fmt.Printf("Claim     %d: %s\n", i, parts[i])
	fmt.Printf("Signature %d: %s\n", j, parts[j])

	// verify if any of the received keys is valid
	var z = 0
	for (z < len(keys)-1) {
		cleankeys 		:= strings.Trim(fmt.Sprintf("%s", keys[z]), "\\")

		var lastkey map[string]interface{}
		json.Unmarshal([]byte(cleankeys), &lastkey)
		fmt.Printf("Search kid: %s\n", lastkey["Kid"])
		key, _ 			:= base64.RawURLEncoding.DecodeString(fmt.Sprintf("%s", lastkey["Pkey"]))
		finallykey, _ 	:= ParseECPublicKey(fmt.Sprintf("%s", key))
		
		verify := ecdsa.VerifyASN1(finallykey.(*ecdsa.PublicKey), hash[:], signature)
		if (verify == true){
			fmt.Printf("Signature successfully validated!\n\n")
			z = len(keys)-1
		} else {
			fmt.Printf("\nSignature validation failed!\n\n")
			if (z == len(keys)-2) {
				fmt.Printf("\nSignature validation failed! No keys remaining!\n\n")
				return false
			}
		}
		z++
		// Debug
		// fmt.Printf("Received Keys: %s\n", cleankeys)
		// fmt.Printf("pkey: %s\n", pkey)
		// fmt.Printf("finallykey: %s\n", finallykey)
	}
	return true
}

// Function to perform token validation from inner level to outside (first -> last assertion)
// TODO: should be necessary to receive array of keys to validate each level with its correspondent key
// 		Other possibility is the function call the directory service to retrieve the key, inside for
func validatreverse(token string, pubkey *ecdsa.PublicKey) bool {
	defer timeTrack(time.Now(), "Validatreverse")

	parts := strings.Split(token, ".")

	//  Verify recursively all lvls except most inner
	var i = (len(parts)/2)-1
	var j = (len(parts)/2)
	for (i >= 0) {
		fmt.Printf("\nClaim     %d: %s\n", i, parts[i])
		fmt.Printf("Signature %d: %s\n", j,  parts[j])

		// Extract first payload (parts[i]) and last signature (parts[j])
		clean := strings.Join(strings.Fields(strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")), ".")
		var hash [32]byte
		if (clean != "") {
			hash = sha256.Sum256([]byte(parts[i] + "." + clean))
		} else {
			hash = sha256.Sum256([]byte(parts[i]))
		}

		signature, err := base64.RawURLEncoding.DecodeString(parts[j])
		if err != nil {
			return false
		}

		// Verify if signature j is valid to payload + previous assertion (parts[i+1:j])
		verify := ecdsa.VerifyASN1(pubkey, hash[:], signature)
		if (verify == true)	{
			fmt.Printf("Signature successfully validated!\n\n")
		} else {
			fmt.Printf("Signature validation failed!\n\n")
			return false
		}
		i--
		j++
	}
	return true
}

func printtoken(token string) {

	// Split received token
	parts := strings.Split(token, ".")
	fmt.Println("Total parts: ", len(parts))
	if (len(parts) < 2) {
		fmt.Printf("Invalid number of parts!")
		os.Exit(1)
	}

	// print single assertion
	if (len(parts) < 3) {
		dectmp, _ := base64.RawURLEncoding.DecodeString(parts[0])
		fmt.Printf("Claim     [%d]	: %s\n", 0, dectmp)
		fmt.Printf("Signature [%d]	: %s\n", 1, parts[1])
		os.Exit(1)
	}
	
	// print token claims
	var i = 0
	for (i < len(parts)/2) {
		dectmp, _ := base64.RawURLEncoding.DecodeString(parts[i])
		fmt.Printf("Claim     [%d]	: %s\n", i, dectmp)
		i++
	}

	// print token  signatures
	j := len(parts)/2
	for ( j < len(parts)) {
		fmt.Printf("Signature [%d]	: %s\n", j, parts[j])
		j++
	}

}

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    fmt.Printf("\n%s execution time is %s\n", name, elapsed)
}

// func validateaud(token string, keys []*ecdsa.PublicKey) {
// 	// aud = clientID
// 	// receive array containing "n" public keys to validate all token claims
// 	defer timeTrack(time.Now(), "validateaud")

// 	parts := strings.Split(token, ".")
// 	if (len(parts) != len(keys)) {
// 		fmt.Printf("Invalid number of keys! Required: %d Received: %d", len(parts), len(keys))
// 		os.Exit(1)
// 	}


// }

func addkey(key string) (string, error) {

    // url := "http://"+filesrv+":"+filesrvport+"/addnft"
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

    // fmt.Println("response Status:", resp.Status)
    // fmt.Println("response Headers:", resp.Header)
    body, _ := ioutil.ReadAll(resp.Body)
    // fmt.Println("response Body:", string(body))

	return string(body), nil
}

func getkey(key string) (string, error) {

    // url := "http://"+filesrv+":"+filesrvport+"/addnft"
	url := "http://localhost:8888/key/" + fmt.Sprintf("%s", key)
    fmt.Printf("\nKey Server URL: %s\n", url)

    var jsonStr = []byte(key)
    req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonStr))
    // req.Header.Set("X-Custom-Header", "keydata")
    // req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Errorf("error: %s", err)
        return "", err
    }
    defer resp.Body.Close()

    // fmt.Println("response Status:", resp.Status)
    // fmt.Println("response Headers:", resp.Header)
    body, _ := ioutil.ReadAll(resp.Body)
    // fmt.Println("response Body:", string(body))

	return string(body), nil
}

// EncodePublicKey encodes an *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey to PEM format.
//  TODO: FIX type, that should be different based on input key type
// At this time it only support ECDSA
func EncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
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

func ParseECPublicKey(pubPEM string) (interface{}, error){
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
	
	return pub,nil

}

func newschnorrencode(claimset map[string]interface{}, oldmain string, key kyber.Scalar) (string, error) {
	defer timeTrack(time.Now(), "newencode")
	var curve = edwards25519.NewBlakeSHA256Ed25519()

	//  Marshall received claimset into JSON
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)
		
	// If no oldmain, generates a simple assertion
	if oldmain == "" {
		tmpsig := dasvid.Sign(payload, key)
		fmt.Printf("Generated Signature: %s\n", tmpsig.String())
		derivedPublicKey := dasvid.PublicKey(payload, tmpsig)
		fmt.Printf("Derived Public Key: %s\n", derivedPublicKey)
		fmt.Printf("Checking signature :%t\n\n", dasvid.Verify(payload, tmpsig, derivedPublicKey))

		buf := bytes.Buffer{}
		if err :=  curve.Write(&buf, &tmpsig); err != nil {
			fmt.Printf("Error! value: %s\n",  err)
			os.Exit(1)
		}
		signature := base64.RawURLEncoding.EncodeToString(buf.Bytes())

		encoded := strings.Join([]string{payload, signature}, ".")

		return encoded, nil
	}
	

	// TODO: Ver o sem old acima, e replicar aqui...

	//  Otherwise, append assertion to previous content (oldmain) and sign it
	// hash	:= sha256.Sum256([]byte(payload + "." + oldmain))
	// s, err 	:= ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
	// if err != nil {
	// 	fmt.Printf("Error signing: %s\n", err)
	// 	return "", err
	// }
	tmpsig := dasvid.Sign(payload, key)
	fmt.Printf("%s", tmpsig.String())
	signature := base64.RawURLEncoding.EncodeToString([]byte(tmpsig.String()))
	// r := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s",sig.R)))
	// s := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s",sig.S)))
	encoded := strings.Join([]string{payload, oldmain, signature}, ".")
	
	// debug
	// fmt.Printf("payload size in base64	: %d\n", len(payload))
	// fmt.Printf("oldpay size in base64	: %d\n", len(oldmain))
	// fmt.Printf("sig size in base64		: %d\n", len(signature))
	// fmt.Printf("Assertion size: %d\n", len(payload) + len(oldmain)+ len(signature))

	return encoded, nil
}
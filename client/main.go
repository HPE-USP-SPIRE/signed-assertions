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
	// "bytes"	

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"
)

const (
	// Workload API socket path
	socketPath    = "unix:///tmp/spire-agent/public/api.sock"
)

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

		default:
			fmt.Println("Error defining issuer! Select spiffeid or svid.")
			os.Exit(1)
	}
		
		// Define assertion claims
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"iat"		:	 	issue_time,
			"alg"		:		"ES256",
			assertionkey:		assertionvalue,
		}
		assertion, err := newencode(assertionclaims, "", clientkey)
		if err != nil {
			fmt.Println("Error generating signed assertion!")
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

			default:
				fmt.Println("Error defining issuer! Select spiffeid or svid.")
				os.Exit(1)
		}

			// Define token claims
			fmt.Println("**mainvalue size: ", len(mainvalue))
			fmt.Println("Other claims size: ", len(issuer)+len(assertionvalue)+len(string(issue_time)))
			tokenclaims := map[string]interface{}{
				"iss":				issuer,
				"iat":	 			issue_time,
				"alg":				"ES256",
				assertionkey:		assertionvalue,
			}
			assertion, err := newencode(tokenclaims, mainvalue, clientkey)
			if err != nil {
				fmt.Println("Error generating signed assertion!")
				os.Exit(1)
			} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		fmt.Println("Assertion size", len(assertion))
		os.Exit(1)

	case "multiappend":
		// Append assertion to an existing token
		//  usage: ./main multiappend originaltoken assertionKey assertionValue howmany spiffeid/svid

		// Fetch claims data
		clientSVID 		:= dasvid.FetchX509SVID()
		clientID 		:= clientSVID.ID.String()
		clientkey 		:= clientSVID.PrivateKey

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
					
				default:
					fmt.Println("Error defining issuer! Select spiffeid or svid.")
					os.Exit(1)
			}
			
			// Define token claims
			tokenclaims 	:= 	map[string]interface{}{
				"iss"		:	issuer,
				"iat"		:	issue_time,
				"alg"		:	"ES256",
				assertionkey+fmt.Sprintf("%v", i):	assertionvalue+fmt.Sprintf("%v", i),
			}
			assertion, err := newencode(tokenclaims, mainvalue, clientkey)
			if err != nil {
				fmt.Println("Error generating signed assertion!")
				os.Exit(1)
			} 

			mainvalue = fmt.Sprintf("%s", assertion)
			fmt.Printf("Resulting assertion: %s\n\n", mainvalue)
			i++
		}

		os.Exit(1)
	case "verify":
		// 	Verify assertion signature
		//  usage: ./assertgen verify assertion
		clientSVID 		:= dasvid.FetchX509SVID()
		clientkey 		:= clientSVID.PrivateKey
		pubkey 			:= clientkey.Public()

		assertion := os.Args[2]
		validateassertion(assertion, pubkey.(*ecdsa.PublicKey))

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

	//  Marshall received claimset into JSON
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)

	if oldmain == "" {
		h := sha256.Sum256([]byte(payload))
		s, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(s)

		fmt.Printf("payload size in base64	: %d\n", len(payload))
		fmt.Printf("sig size in base64		: %d\n", len(sig))
		fmt.Printf("Total size in base64	: %d\n", len(payload) + len(sig))
		msg := strings.Join([]string{payload, sig}, ".")

		return msg, nil
	}
	
	
	h := sha256.Sum256([]byte(payload + "." + oldmain))
	s, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), h[:])
	if err != nil {
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	
	fmt.Printf("payload size in base64	: %d\n", len(payload))
	fmt.Printf("oldpay size in base64	: %d\n", len(oldmain))
	fmt.Printf("sig size in base64		: %d\n", len(signature))
	fmt.Printf("Total size in base64	: %d\n", len(payload) + len(oldmain)+ len(signature))
	msg := strings.Join([]string{payload, oldmain, signature}, ".")

	return msg, nil

}

func printtoken (token string) {
	parts := strings.Split(token, ".")

	if (len(parts) < 3) {
		fmt.Println("No main to extract!")
		os.Exit(1)
	}
	
	var i = 0
	fmt.Println("len(parts): ", len(parts))
	for (i < len(parts)/2) {
		dectmp, _ := base64.RawURLEncoding.DecodeString(parts[i])
		fmt.Printf("Claim [%d]	: %s\n", i, dectmp)
		i++
	}

	i = len(parts)/2
	for ( i < len(parts)) {
		// sigtemp, _ := base64.RawURLEncoding.DecodeString(parts[i])
		fmt.Printf("Signature [%d]	: %s\n", i, parts[i])

		i++
	}

}

func validateassertion (token string, pubkey *ecdsa.PublicKey) {

	parts := strings.Split(token, ".")

	if (len(parts) < 3) {
		fmt.Printf("Claim: %s\n", parts[0])
		fmt.Printf("Signature: %s\n", parts[1])
		signature, _ 	:= base64.RawURLEncoding.DecodeString(parts[1])

		h := sha256.Sum256([]byte(parts[0]))
		verify 	:= ecdsa.VerifyASN1(pubkey, h[:], signature)

		if (verify == true){
			fmt.Printf("Signature successfully validated!\n")
		} else {
			fmt.Printf("Signature validation failed!\n")
		}

		os.Exit(1)
	}

	//  Verify recursively
	var i = 0
	
	fmt.Println("len(parts): ", len(parts))
	var j = len(parts)-1
	// var claim, sig string
	for (i < len(parts)/2 && (i+1 < j-1)) {
		fmt.Printf("Claim %d: %s\n", i, parts[i])
		fmt.Printf("Signature %d: %s\n", j,  parts[j])

		// // Pop Front
		// claim, parts = parts[i], parts[i+1:]
		// fmt.Printf("Claim extracted: %s\n", claim)

		// // Pop
		// sig, parts = parts[len(parts)-1], parts[:len(parts)-1]
		// fmt.Printf("Sig extracted: %s\n", sig)

		
		clean := strings.Trim(fmt.Sprintf("%s", parts[i+1:j]), "[]")
		fmt.Printf("clean: %s\n", clean)
		clean = strings.Join(strings.Fields(clean), ".")
		fmt.Printf("Resulting parts clean: %s\n", fmt.Sprintf("%s", clean))
		signature, _ 	:= base64.RawURLEncoding.DecodeString(parts[j])
		h := sha256.Sum256([]byte(parts[i] + "." + clean))
		verify 	:= ecdsa.VerifyASN1(pubkey, h[:], signature)
		if (verify == true){
			fmt.Printf("Signature successfully validated!\n\n")
		} else {
			fmt.Printf("Signature validation failed!\n\n")
		}

		i++
		j--
	}

	fmt.Printf("Claim %d: %s\n", i, parts[i])
	fmt.Printf("Signature %d: %s\n", j,  parts[j])
	signature, _ 	:= base64.RawURLEncoding.DecodeString(parts[j])

	h := sha256.Sum256([]byte(parts[i]))
	verify 	:= ecdsa.VerifyASN1(pubkey, h[:], signature)

	if (verify == true){
		fmt.Printf("Signature successfully validated!\n")
	} else {
		fmt.Printf("Signature validation failed!\n")
	}

	os.Exit(1)

	// os.Exit(1)
	// var i = len(parts)/2
	// fmt.Println("len(parts): ", len(parts))
	// for ( i < len(parts)) {
	// 	sigtemp, _ := base64.RawURLEncoding.DecodeString(parts[i])
	// 	fmt.Printf("Signature [%d]: %s\n", i, sigtemp)


	// 	i++
	// }

}
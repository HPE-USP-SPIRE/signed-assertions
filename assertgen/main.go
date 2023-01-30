package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net"
	"fmt"
	"os"
	"encoding/base64"
	"encoding/json"
	"time"
	"crypto/ecdsa"
	"strings"
	"strconv"
	"bufio"
	
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"

	// EdDSA
	"go.dedis.ch/kyber/v3/group/edwards25519"

	"go.dedis.ch/kyber/v3"
	// hash256 "crypto/sha256"
	// "encoding/hex"

)

const (
	// Workload API socket path
	socketPath	= "unix:///tmp/spire-agent/public/api.sock"
	
)

// Set curve
var curve = edwards25519.NewBlakeSHA256Ed25519()

type keydata struct {
	Kid			string `json:kid",omitempty"`
	Alg			string `json:alg",omitempty"`
	Pkey		[]byte `json:pkey",omitempty"`
	Exp			int64  `json:exp",omitempty"`
}

type Signature struct {
    R kyber.Point
    S kyber.Scalar
}

func main() {
	ParseEnvironment()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var endpoint string
	
	// Retrieve local IP
	// In this PoC example, client and server are running in the same host, so serverIP = clientIP 
	StrIPlocal := fmt.Sprintf("%v", GetOutboundIP())
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

  - print
	Print informed nest token
	usage: ./assertgen print token
  - mint
  	Ask running asserting-wl for a new DASVID given Oauthtoken
	usage: ./assertgen mint OAuthtoken
  - keys
	Ask asserting-wl Public Key
	usage: ./assertgen keys
  - validate
  	Ask asserting-wl for DASVID validation (signature/expiration)
    usage: ./assertgen validate DASVID
  - zkp
  	Ask for ZKP given DASVID
    usage: ./assertgen zkp DASVID
  - traceadd
      Add next hop assertion to existing token 
	  usage: ./assertgen traceadd <originaltoken> secretkey nextsecretkey
  - ecdsagen
      Generate a new ECDSA assertion
	  usage: ./assertgen ecdsagen <assertionkey> <assertion_value> <spiffeid/svid>
  - ecdsaver
  	  Verify assertion signature
      usage: ./assertgen verify direction assertion
      extract the keyid from token and use it to retrieve public key from IdP
  - append
	  Append assertion to an existing token
	  usage: ./assertgen append originaltoken assertionKey assertionValue spiffeid/svid
	  Changed "alg" to "kid", that is used to retrieve correct key informations from IdP 
	  kid = public key hash
  - multiappend
	  Append assertion to an existing token
	  usage: ./assertgen append originaltoken assertionKey assertionValue spiffeid/svid
	  Changed "alg" to "kid", that is used to retrieve correct key informations from IdP 
	  kid = public key hash
  - schgen
	  Generate a new schnorr signed assertion
	  usage: ./main schgen assertionKey assertionValue
  - schver
	  Verify assertion schnorr signature
	  usage: ./assertgen schver assertion 
  - appsch
  	  Appent an assertion with schnorr signature
  	  usage: ./main appsch originaltoken assertionKey assertionValue
`)
	os.Exit(1)

	//  __ Asserting Workload Interactions __ //
	case "print":
		// 	Print given token
		//  usage: ./main print token
		token := os.Args[2]
		dasvid.PrintAssertion(token)
		os.Exit(1)
	
    case "mint":
		// 	Ask asserting-wl for a new minted DASVID
		//  usage: ./assertgen mint OAuthtoken
		token := os.Args[2]
		endpoint = "https://"+serverURL+"/mint?AccessToken="+token
    case "mintassertion":
		// 	Ask asserting-wl for a new minted DASVID
		//  usage: ./assertgen mint OAuthtoken
		token := os.Args[2]
		endpoint = "https://"+serverURL+"/mintassertion?AccessToken="+token

    case "ecdsaassertion":
		// 	Ask asserting-wl for a new minted DASVID
		//  usage: ./assertgen mint OAuthtoken
		token := os.Args[2]
		endpoint = "https://"+serverURL+"/ecdsaassertion?AccessToken="+token

    case "keys":
		// 	Ask asserting-wl Public Key
		//  usage: ./assertgen keys
		endpoint = "https://"+serverURL+"/keys"

    case "validate":
		// 	Ask asserting-wl for DASVID validation (signature/expiration)
		//  usage: ./assertgen validate DASVID
		dasvid := os.Args[2]
		endpoint = "https://"+serverURL+"/validate?DASVID="+dasvid

	case "zkp":
		// 	Ask for ZKP given DASVID
		//  usage: ./assertgen zkp DASVID
		dasvid := os.Args[2]
		endpoint = "https://"+serverURL+"/introspect?DASVID="+dasvid
	
	//  __ ECDSA __ //
	case "ecdsagen":
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
		encKey, _ := dasvid.EncodeECDSAPublicKey(pubkey)

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
		assertion, err := dasvid.NewECDSAencode(assertionclaims, "", clientkey)
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
		savekey, err := dasvid.Addkey(fmt.Sprintf("%s",mkey))
		if err != nil {
			fmt.Errorf("error: %s", err)
			os.Exit(1)
		}
		fmt.Println("Key successfully stored: ", savekey)


		os.Exit(1)

	case "ecdsapq":
		// Generate a new assertion using ECDSA + Dilithium
		// usage: ./main ecdsapq assertionKey assertionValue spiffeid/svid/anonymous

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
		encKey, _ := dasvid.EncodeECDSAPublicKey(pubkey)

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
		assertion, err := dasvid.NewECDSAencode(assertionclaims, "", clientkey)
		if err != nil {
			fmt.Println("Error generating signed assertion!")
			os.Exit(1)
		} 

		diliassertion, err := dasvid.NewDilithiumencode(assertionclaims, "")
		if err != nil {
			fmt.Println("Error generating Dilithium signed assertion!")
			os.Exit(1)
		} 


		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		
		fmt.Println("Generated dilithium assertion: ", fmt.Sprintf("%s",diliassertion))

		//  save public key in IdP
		key := &keydata{
			Kid		:	kid,
			Alg		:	"EC256",
			Pkey	:	encKey,
			Exp		:	time.Now().Add(time.Hour * 1).Round(0).Unix(),
		}
		mkey, _ := json.Marshal(key)
		savekey, err := dasvid.Addkey(fmt.Sprintf("%s",mkey))
		if err != nil {
			fmt.Errorf("error: %s", err)
			os.Exit(1)
		}
		fmt.Println("Key successfully stored: ", savekey)


		os.Exit(1)


	case "ecdsaver":
		// 	Verify ECDSA assertion signature
		//  usage: ./assertgen ecdsaver assertion
		//  extract the keyid from token and use it to retrieve public key from IdP

		assertion := os.Args[2]
		dasvid.ValidateECDSAeassertion(assertion)

		os.Exit(1)

	case "ecdsaadd":
		// Append assertion to an existing token
		//  usage: ./assertgen ecdsaadd originaltoken assertionKey assertionValue spiffeid/svid
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
		encKey, _ 		:= dasvid.EncodeECDSAPublicKey(pubkey.(*ecdsa.PublicKey))
		valid 			:= dasvid.ValidateECDSAeassertion(mainvalue)
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
				fmt.Println("Error defining issuer! Select spiffeid, svid or anonymous.")
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
			assertion, err := dasvid.NewECDSAencode(tokenclaims, mainvalue, clientkey)
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
		savekey, err := dasvid.Addkey(fmt.Sprintf("%s",mkey))
		if err != nil {
			fmt.Errorf("error: %s", err)
			os.Exit(1)
		}
		fmt.Println("Key successfully stored: ", savekey)

		os.Exit(1)

	case "multiappend":
		defer timeTrack(time.Now(), "multiappend ")
		// Append a specific number of ECDSA assertions to an existing token (for test purposes in some scenarios)
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
			pubkey			:= clientkey.Public().(*ecdsa.PublicKey)
			encKey, _ 		:= dasvid.EncodeECDSAPublicKey(pubkey)

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
			assertion, err := dasvid.NewECDSAencode(tokenclaims, mainvalue, clientkey)
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
			savekey, _ := dasvid.Addkey(fmt.Sprintf("%s",mkey))
			if err != nil {
				fmt.Errorf("error: %s", err)
				os.Exit(1)
			}
			fmt.Println("Key successfully stored: ", savekey)
			i++
		}

		os.Exit(1)

	//  __ Normal EdDSA Schnorr __ //
	case "schgen":
		// Generate a new schnorr signed assertion containing key:value with no specific audience
		// usage: ./assertgen schgen assertionKey assertionValue

		// Generate Keypair
		privateKey, publicKey := dasvid.RandomKeyPair()
		// fmt.Println("Generated publicKey: ", publicKey)

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// issuer
		issuer, err := dasvid.Point2string(publicKey)
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 

		// assertion key:value
		assertionkey 	:= os.Args[2]
		assertionvalue 	:= os.Args[3]
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"iat"		:	 	issue_time,
			assertionkey:		assertionvalue,
		}
		assertion, err := dasvid.NewSchnorrencode(assertionclaims, "", privateKey)
		if err != nil {
			fmt.Println("Error generating signed schnorr assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		os.Exit(1)


	case "schver":
		// 	Verify assertion signatures only
		//  usage: ./assertgen schver assertion

		assertion := os.Args[2]

		dasvid.Validateschnorrassertion(assertion)
		os.Exit(1)

	case "schadd":
		// Append an assertion with schnorr signature, using a new random keypair
		// usage: ./main schapp originaltoken assertionKey assertionValue

		// Generate Keypair
		privateKey, publicKey := dasvid.RandomKeyPair()

		// issuer
		issuer, err := dasvid.Point2string(publicKey)
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 

		// Generate next Keypair
		_, nextpublicKey := dasvid.RandomKeyPair()

		// Audience
		audience, err := dasvid.Point2string(nextpublicKey)		
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// Original token
		oldmain 		:= os.Args[2]

		// assertion key:value
		assertionkey 	:= os.Args[3]
		assertionvalue 	:= os.Args[4]
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"aud"		:	 	audience,
			"iat"		:	 	issue_time,
			assertionkey:		assertionvalue,
		}
		assertion, err := dasvid.NewSchnorrencode(assertionclaims, oldmain, privateKey)
		if err != nil {
			fmt.Println("Error generating signed schnorr assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		// fmt.Println("Next private key   : ", nextprivateKey.String())

		os.Exit(1)
	
	//  __ Tracing model (EdDSA Schnorr + issuer/audience verification + string based key) __ //
	case "tracegen":
		// Generate a new schnorr signed assertion containing key:value and audience
		// issuer: public key from secretkey
		// audience: public key from nextsecretkey

		// usage: ./assertgen tracenew assertionKey assertionValue secretkey nextsecretkey
		// secretkey     : KeyID used to sign assertion. 
		// nextsecretkey : next hop private KeyID.

		// Generate Keypair given secretkey
		privateKey, publicKey := dasvid.IDKeyPair(os.Args[4])

		// Generate nextpublicKey given nextsecretkey
		_, nextpublicKey := dasvid.IDKeyPair(os.Args[5])

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// issuer
		issuer, err := dasvid.Point2string(publicKey)
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 
		
		// Audience
		audience, err := dasvid.Point2string(nextpublicKey)		
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 

		// assertion claims
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"aud"		:	 	audience,
			"iat"		:	 	issue_time,
			os.Args[2]  :		os.Args[3],
		}
		// encode and sign assertion
		assertion, err := dasvid.NewSchnorrencode(assertionclaims, "", privateKey)
		if err != nil {
			fmt.Println("Error generating signed schnorr assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		os.Exit(1)

	case "traceadd":
		// 	Add next hop assertion to existing tracetoken
		//  usage: ./assertgen traceadd tracetoken key value sourceprivatekey destinyprivatekey

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		oldmain := os.Args[2]

		// Generate Keypair
		privateKey, publicKey := dasvid.IDKeyPair(os.Args[5])

		// check soucerpublickey vs audience
		parts := strings.Split(oldmain, ".")
		decodedpart, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			fmt.Println("Error decoding token!")
			os.Exit(1)
		}		
		var tmpkey map[string]interface{}
		json.Unmarshal(decodedpart, &tmpkey)
		pkey, err := dasvid.Point2string(publicKey)
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 
		if (pkey != tmpkey["aud"]) {
			fmt.Println("Incorrect append key!")
			os.Exit(1)
		}	

		// Generate next Keypair
		_, nextpublicKey := dasvid.IDKeyPair(os.Args[6])

		// issuer
		issuer, err := dasvid.Point2string(publicKey)
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 
		
		// Audience
		audience, err := dasvid.Point2string(nextpublicKey)		
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 
		
		tokenclaims := map[string]interface{}{
			"iss"		: issuer,
			"iat"		: issue_time,
			os.Args[3]	: os.Args[4],
			"aud"		: audience,
		}
		assertion, err := dasvid.NewSchnorrencode(tokenclaims, oldmain, privateKey)
		if err != nil {
			fmt.Println("Error generating signed assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))
		os.Exit(1)

	case "tracever":
		// 	Verify assertion signatures and iss/aud links
		//  usage: ./assertgen tracever assertion

		assertion := os.Args[2]

		dasvid.Validateschnorrtrace(assertion)
		os.Exit(1)

	//  __ Concatenated EdDSA Schnorr (sig.S as next private Key) __ //
	case "concatenate":
		// Append an assertion with schnorr signature, using previous signature.S as key
		// usage: ./main concatenate originaltoken assertionKey assertionValue 

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// set g
		g := curve.Point().Base()

		// Original token
		oldmain 		:= os.Args[2]
		parts 			:= strings.Split(oldmain, ".")		

		var assertion string

		// Retrieve signature from originaltoken 
		prevsignature, err := dasvid.String2schsig(parts[len(parts) -1])
		if err != nil {
			fmt.Println("Error converting string to schnorr signature!")
			os.Exit(1)
		} 
		privateKey := prevsignature.S
		// Discard sig.S
		parts[len(parts) -1], err = dasvid.Point2string(prevsignature.R)
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 

		oldmain = strings.Join(parts, ".")
		publicKey := curve.Point().Mul(privateKey, g)
		// fmt.Println("Generated publicKey: ", publicKey)
		
		// Issuer
		issuer, err := dasvid.Point2string(publicKey)
		if err != nil {
			fmt.Println("Error decoding point string!")
			os.Exit(1)
		} 
		
		// assertion key:value
		assertionkey 	:= os.Args[3]
		assertionvalue 	:= os.Args[4]
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"iat"		:	 	issue_time,
			assertionkey:		assertionvalue,
		}
		assertion, err = dasvid.NewSchnorrencode(assertionclaims, oldmain, privateKey)
		if err != nil {
			fmt.Println("Error generating signed schnorr assertion!")
			os.Exit(1)
		} 

		fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))

		os.Exit(1)
		
	//  __ Galindo Garcia validation of EdDSA concatenated Schnorr signatures__ //
	case "ggschnorr":
		// 	Verify assertion signatures using Galindo Garcia
		//  usage: ./assertgen ggschnorr assertion
		assertion := os.Args[2]

		dasvid.Validategg(assertion)
		
		os.Exit(1)
		
	case "selectors":
		//  Generate a selector-based assertion
		//  usage: ./assertgen selectors <issuer type>


		// Generate a new assertion
		// usage: ./main generic assertionKey assertionValue spiffeid/svid

		// Fetch claims data
		clientSVID 		:= dasvid.FetchX509SVID()
		clientID 		:= clientSVID.ID.String()
		clientkey 		:= clientSVID.PrivateKey
		pid 			:= os.Getpid()

		// timestamp
		issue_time 		:= time.Now().Round(0).Unix()

		// assertion key:value
		// assertionkey 	:= os.Args[2]
		// assertionvalue 	:= os.Args[3]

		// uses spiffeid or svid as issuer
		svidAsIssuer 	:= os.Args[2]

		// generate encoded key
		pubkey := clientkey.Public().(*ecdsa.PublicKey)
		encKey, _ := dasvid.EncodeECDSAPublicKey(pubkey)

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

		// Retrieve selectors
		selectors, err := dasvid.ReturnSelectors(pid)
		if err != nil {
			fmt.Println("Error retrieving selectors!")
			os.Exit(1)
		}

		fmt.Printf("Selectors array %s\n", selectors)

		// Define assertion claims
		kid 			:= base64.RawURLEncoding.EncodeToString([]byte(clientID))
		assertionclaims := map[string]interface{}{
			"iss"		:		issuer,
			"iat"		:	 	issue_time,
			"kid"		:		kid,
			"sel"		:		selectors,
		}
		assertion, err := dasvid.NewECDSAencode(assertionclaims, "", clientkey)
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
		savekey, err := dasvid.Addkey(fmt.Sprintf("%s",mkey))
		if err != nil {
			fmt.Errorf("error: %s", err)
			os.Exit(1)
		}
		fmt.Println("Key successfully stored: ", savekey)


		os.Exit(1)
	}

	if endpoint != "" {

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
}

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    fmt.Printf("\n%s execution time is %s\n", name, elapsed)
}

func ParseEnvironment() {

	if _, err := os.Stat(".cfg"); os.IsNotExist(err) {
		log.Printf("Config file (.cfg) is not present.  Relying on Global Environment Variables")
	}

	setEnvVariable("SOCKET_PATH", os.Getenv("SOCKET_PATH"))
	if os.Getenv("SOCKET_PATH") == "" {
		log.Printf("Could not resolve a SOCKET_PATH environment variable.")
		// os.Exit(1)
	}
	
}

func setEnvVariable(env string, current string) {
	if current != "" {
		return
	}

	file, _ := os.Open(".cfg")
	defer file.Close()

	lookInFile := bufio.NewScanner(file)
	lookInFile.Split(bufio.ScanLines)

	for lookInFile.Scan() {
		parts := strings.Split(lookInFile.Text(), "=")
		key, value := parts[0], parts[1]
		if key == env {
			os.Setenv(key, value)
		}
	}
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

func assertSelectors(pid int) string{

	selectors, err := dasvid.ReturnSelectors(pid)
	if err != nil {
		log.Fatalf("Errors retrieving selectors: %v", err)
	}
	log.Printf("Selectors retrieved: ", selectors)

	return selectors
}

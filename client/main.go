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

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"
)


type Mainclaim struct {
	Header				string
	Payload				string
	Signature			JSONableSlice
}

type JSONableSlice []byte

type Payload struct {
	Iss					string `json:"iss"`
	Iat					string `json:"iat"`
	Aud					string `json:"foo"` 
	Main				Mainclaim `json:"main"`
}

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
		parseNest(token)
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
		datoken := os.Args[3]
		
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
			// "main":		datoken,
		}
		assertion, err := newencode(tokenclaims,datoken, clientkey, true)
		if err != nil {
			fmt.Println("Error generating signed JSON!")
			os.Exit(1)
		} 

		fmt.Println(fmt.Sprintf("%s",assertion))
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
			assertionkey:		assertionvalue,
		}
		assertion, err := newencode(assertionclaims, "", clientkey, true)
		if err != nil {
			fmt.Println("Error generating signed JSON!")
			os.Exit(1)
		} 

		fmt.Println(fmt.Sprintf("%s",assertion))
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
			// 	// set token to next one
			// 	// tmptoken = strings.Trim(fmt.Sprintf("%s", tokenclaims["main"]), "\"")
			// 	// fmt.Println("tmptoken: ", tmptoken)
			// 	tmp := dasvid.ParseTokenClaims(fmt.Sprintf("%s", tmptoken))
			// 	tokenclaims["main"] = fmt.Sprintf("%s", tmp["main"])
			fmt.Println("mainvalue", mainvalue)
			tokenclaims = dasvid.ParseTokenClaims(mainvalue)	
			}

		}

		// tmp = strings.Trim(fmt.Sprintf("%s", tokenclaims["main"]), "[]")
		// fmt.Println("tmp2", tmp)
		tmpparts := strings.Split(mainvalue, ".")
		// tmp =  strings.Join([]string{tmpparts[0], tmpparts[1], tmpparts[2]}, ".")
		// collect last level
		// parts := strings.Split(fmt.Sprintf("%v", tmp), ".")
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
				// "main":				mainvalue,
				assertionkey:		assertionvalue,
			}
			assertion, err := newencode(tokenclaims, mainvalue, clientkey, true)
			if err != nil {
				fmt.Println("Error generating signed assertion!")
				os.Exit(1)
			} 

		fmt.Println("Assertion", fmt.Sprintf("%s", assertion))
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
			// maindec 		:= 	decodemain(mainvalue)
			tokenclaims 	:= 	map[string]interface{}{
				"iss"		:	issuer,
				"iat"		:	issue_time,
				// "main"		:	maindec,
				assertionkey:	assertionvalue,
			}
			assertion, err := newencode(tokenclaims, mainvalue, clientkey, true)
			if err != nil {
				fmt.Println("Error generating signed JSON!")
				os.Exit(1)
			} 

			mainvalue = fmt.Sprintf("%s", assertion)
			fmt.Println("mainvalue ", mainvalue)
			// mainvalue = strings.Trim(mainvalue, "\"")
			fmt.Println("Resulting assertion: ", mainvalue)
			i++
		}

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

// func encodeJSONassertion(claimset map[string]interface{}, key crypto.Signer, header bool) ([]byte, error) {

// 	phead := `{"alg":"ES256"}`
// 	phead = base64.RawURLEncoding.EncodeToString([]byte(phead))


// 	// if claimset["main"] != nil {
// 	// }
// 	fmt.Println("claimset ", claimset)	
// 	// cs, _ := json.Marshal(claimset)
// 	// fmt.Println("cs ", cs)
// 	maindec := decodemain(fmt.Sprint(claimset["main"]))
// 	mainz := &Mainclaim{string(maindec[0]), string(maindec[1]), maindec[2]}
// 	temptest := &Payload{fmt.Sprint(claimset["iss"]), fmt.Sprint(claimset["iat"]), fmt.Sprintf("%v", claimset["foo"]), *mainz}
// 	cs, _ := json.Marshal(temptest)
// 	fmt.Println("cs ", fmt.Sprintf("%s", cs))

// 	// payload := `{"iss":`+fmt.Sprint(claimset["iss"])+`,"iat":`+fmt.Sprint(claimset["iat"])+`,"foo":`+fmt.Sprint(claimset["foo"])+`,"main":`+fmt.Sprint(decdmain)+`}`
// 	payload := base64.RawURLEncoding.EncodeToString(cs)

// 	fmt.Println("header size in base64: ", len(phead))
// 	fmt.Println("payload size in base64: ", len(payload))
// 	h := sha256.New()
// 	h.Write([]byte(phead + "." + payload))
// 	s, err := key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
// 	if err != nil {
// 		return nil, err
// 	}
// 	sig := base64.RawURLEncoding.EncodeToString(s)
// 	fmt.Println("sig size in base64: ", len(sig))
// 	fmt.Println("Total size in base64: ", len(phead) + len(payload)+ len(sig))
// 	var msg string
// 	if header == true {
// 		msg = strings.Join([]string{phead, payload, sig}, ".")
// 	} else {
// 		msg = strings.Join([]string{payload, sig}, ".")
// 	}
// 	// enc := struct {
// 	// 	Token		string `json:"token"`
// 	// }{
// 	// 	Token:		msg,
// 	// }
// 	return json.Marshal(msg)

// }

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

func parseNest(nestoken string) {

	// Parse token claims
	// PS: no validation performed here.
	// fmt.Println("nestoken: ", nestoken)
	token := dasvid.ParseTokenClaims(nestoken)
	// fmt.Println("token: ", token)

	// Go deeper in the token if main exists
	for token["main"] != nil {

		// fmt.Println("tokenmain: ", token["main"])
		tmp := strings.Trim(fmt.Sprintf("%s", token["main"]), "[]")
		// fmt.Println("tmp: ", tmp)
		parts := strings.Split(tmp, " ")
		// fmt.Println("parts[0]: ", parts[0])
		// fmt.Println("parts[1]: ", parts[1])
		// fmt.Println("parts[2]: ", parts[2])
		tmp =  strings.Join([]string{parts[0], parts[1], parts[2]}, ".")
		// fmt.Println("tmp: ", tmp)
		// print the level
		jsonStr, err := json.Marshal(token)
		if err != nil {
			fmt.Printf("Error: %s", err.Error())
			os.Exit(1)
		}
		fmt.Println(string(jsonStr))

		// set token to next one
		// token = dasvid.ParseTokenClaims(fmt.Sprintf("%v", token["main"]))
		token = dasvid.ParseTokenClaims(fmt.Sprintf("%v", tmp))
	}

	// print last level
	jsonStr, err := json.Marshal(token)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		os.Exit(1)
	}
	fmt.Println(string(jsonStr))
}

func checkmain(token string) bool {
	tokentmp := dasvid.ParseTokenClaims(token)
	if (tokentmp["main"] == nil) {
		return false
	}
	return true

}

func decodemain(maintoken string) []byte{

	parts := strings.Split(maintoken, ".")
	// head, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pay, _ := base64.RawURLEncoding.DecodeString(parts[0])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[1])

	partjoin := [][]byte{pay, sig}
	oldtoken := bytes.Join(partjoin, []byte(";"))
	// result := []byte(`{"header":`+head+`,"payload":`+pay+`,"signature":`+sig+`}`)
	// fmt.Println("result", result)
	// sep := []byte(".")
	// decodedtoken := bytes.Join(partjoin, sep)
	// jsonbytes := mainclaim{}
	// json.Unmarshal(decodedtoken, &jsonbytes)
	// fmt.Println(jsonbytes)
	return oldtoken

}

func (u JSONableSlice) MarshalJSON() ([]byte, error) {
	var result string
	if u == nil {
		result = "null"
	} else {
		tmp := strings.Fields(fmt.Sprintf("%d", u))
		fmt.Println("tmp",tmp)
		result = strings.Join(tmp, ",")
	}
	return []byte(result), nil
}

func newencode(claimset map[string]interface{}, oldmain string, key crypto.Signer, header bool) (string, error) {

	// faz um byte.join do maindec
	// encoda esses bytes pra um negocio so e coloca no oldpay

	//  Marshall received claimset into JSON
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)
	// fmt.Println("claimset ", claimset)	
	// fmt.Println("cs ", fmt.Sprintf("%s", cs))


	if oldmain == "" {
		h := sha256.New()
		h.Write([]byte(payload))
		s, err := key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
		if err != nil {
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(s)
		fmt.Println("payload size in base64	: ", len(payload))
		fmt.Println("sig size in base64		: ", len(sig))
		fmt.Println("Total size in base64: ", len(payload) + len(sig))
		msg := strings.Join([]string{payload, sig}, ".")
		
		return msg, nil
	}

	decodeold := decodemain(oldmain)
	oldpay := base64.RawURLEncoding.EncodeToString(decodeold)
	// fmt.Println("oldtoken ", fmt.Sprintf("%s", oldtoken))
	



	h := sha256.New()
	h.Write([]byte(payload + "." + oldpay))
	s, err := key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		return "", err
	}
	sig := base64.RawURLEncoding.EncodeToString(s)
	fmt.Println("payload size in base64	: ", len(payload))
	fmt.Println("oldpay size in base64	: ", len(oldpay))
	fmt.Println("sig size in base64		: ", len(sig))
	fmt.Println("Total size in base64: ", len(payload) + len(oldpay)+ len(sig))
	msg := strings.Join([]string{payload, oldpay, sig}, ".")
	
	tmp := extractmain(msg)
	fmt.Println("Main token: ", tmp)

	return msg, nil

}

func extractmain (token string) string {
	parts := strings.Split(token, ".")
	// fmt.Println("old token: ", parts[1])
	dectmp, _ := base64.RawURLEncoding.DecodeString(parts[1])
	fmt.Println("dectmp: ", dectmp)
	result := bytes.Split(dectmp, []byte(";"))
	fmt.Println("result: ", result)
	
	fmt.Println("result0		: ", string(result[0]))
	fmt.Println("result1		: ", string(result[1]))
	// fmt.Println("result2		: ", string(result[2]))


	// head := base64.RawURLEncoding.EncodeToString(result[0])
	pay := base64.RawURLEncoding.EncodeToString(result[0])
	sig := base64.RawURLEncoding.EncodeToString(result[1])
	msg := strings.Join([]string{pay, sig}, ".")
	fmt.Println("msg: ", msg)




	return msg
}
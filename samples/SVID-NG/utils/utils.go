package utils

import (
	"os"
	"log"
	"strings"
	"bufio"
	"time"
	"net"
	"fmt"
	"encoding/hex"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"github.com/gorilla/sessions"
	"bytes"
	"io/ioutil"
	"encoding/json"
	"html/template"

	"SVID-NG/types"
)

var (
	SessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	Data			types.PocData
	Tpl				*template.Template
)

func ParseEnvironment() {

	log.Printf("Parsing env variables!")

	if _, err := os.Stat("./utils/.cfg"); os.IsNotExist(err) {
		log.Printf("Config file (.cfg) is not present.  Relying on Global Environment Variables")
	}

	SetEnvVariable("PROOF_LEN", os.Getenv("PROOF_LEN"))
	if os.Getenv("PROOF_LEN") == "" {
		log.Printf("Could not resolve a PROOF_LEN environment variable.")
	}

	SetEnvVariable("PEM_PATH", os.Getenv("PEM_PATH"))
	if os.Getenv("PEM_PATH") == "" {
		log.Printf("Could not resolve a PEM_PATH environment variable.")
	}
		SetEnvVariable("MINT_ZKP", os.Getenv("MINT_ZKP"))
	if os.Getenv("MINT_ZKP") == "" {
		log.Printf("Could not resolve a MINT_ZKP environment variable.")
	}

	SetEnvVariable("SOCKET_PATH", os.Getenv("SOCKET_PATH"))
	if os.Getenv("SOCKET_PATH") == "" {
		log.Printf("Could not resolve a SOCKET_PATH environment variable.")
	}
	
	SetEnvVariable("TRUST_DOMAIN", os.Getenv("TRUST_DOMAIN"))
	if os.Getenv("TRUST_DOMAIN") == "" {
		log.Printf("Could not resolve a TRUST_DOMAIN environment variable.")
	}

	SetEnvVariable("ADD_ZKP", os.Getenv("ADD_ZKP"))
	if os.Getenv("ADD_ZKP") == "" {
		log.Printf("Could not resolve a ADD_ZKP environment variable.")
	}

	SetEnvVariable("HOSTIP", os.Getenv("HOSTIP"))
	if os.Getenv("HOSTIP") == "" {
		log.Printf("Could not resolve a HOSTIP environment variable.")
	}
	
	SetEnvVariable("ASSERTINGWLIP", os.Getenv("ASSERTINGWLIP"))
	if os.Getenv("ASSERTINGWLIP") == "" {
		log.Printf("Could not resolve a ASSERTINGWLIP environment variable.")
	}
	
	SetEnvVariable("MIDDLETIERIP", os.Getenv("MIDDLETIERIP"))
	if os.Getenv("MIDDLETIERIP") == "" {
		log.Printf("Could not resolve a MIDDLETIERIP environment variable.")
	}
	
	SetEnvVariable("MIDDLE_TIER2_IP", os.Getenv("MIDDLE_TIER2_IP"))
	if os.Getenv("MIDDLE_TIER2_IP") == "" {
		log.Printf("Could not resolve a MIDDLE_TIER2_IP environment variable.")
	}
	
	SetEnvVariable("MIDDLE_TIER3_IP", os.Getenv("MIDDLE_TIER3_IP"))
	if os.Getenv("MIDDLE_TIER3_IP") == "" {
		log.Printf("Could not resolve a MIDDLE_TIER3_IP environment variable.")
	}

	SetEnvVariable("MIDDLE_TIER4_IP", os.Getenv("MIDDLE_TIER4_IP"))
	if os.Getenv("MIDDLE_TIER4_IP") == "" {
		log.Printf("Could not resolve a MIDDLE_TIER4_IP environment variable.")
	}

	SetEnvVariable("MIDDLE_TIER5_IP", os.Getenv("MIDDLE_TIER5_IP"))
	if os.Getenv("MIDDLE_TIER5_IP") == "" {
		log.Printf("Could not resolve a MIDDLE_TIER5_IP environment variable.")
	}

	SetEnvVariable("TARGETWLIP", os.Getenv("TARGETWLIP"))
	if os.Getenv("TARGETWLIP") == "" {
		log.Printf("Could not resolve a TARGETWLIP environment variable.")
	}

	SetEnvVariable("CLIENT_ID", os.Getenv("CLIENT_ID"))
	if os.Getenv("CLIENT_ID") == "" {
		log.Printf("Could not resolve CLIENT_ID environment variable.")
	}

	SetEnvVariable("CLIENT_SECRET", os.Getenv("CLIENT_SECRET"))
	if os.Getenv("CLIENT_SECRET") == "" {
		log.Printf("Could not resolve CLIENT_SECRET environment variable.")
	}

	SetEnvVariable("ISSUER", os.Getenv("ISSUER"))
	if os.Getenv("ISSUER") == "" {
		log.Printf("Could not resolve ISSUER environment variable.")
	}
}

func SetEnvVariable(env string, current string) {
	if current != "" {
		return
	}

	file, _ := os.Open("./utils/.cfg")
	defer file.Close()

	lookInFile := bufio.NewScanner(file)
	lookInFile.Split(bufio.ScanLines)

	for lookInFile.Scan() {
		parts := strings.Split(lookInFile.Text(), "=")
		key, value := parts[0], parts[1]
		if key == env {
			log.Printf("Setting env var: %v %v", key, value)
			os.Setenv(key, value)
		}
	}
}

func TimeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}

func GetOutboundIP(port string) string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
	StrIPlocal := fmt.Sprintf("%v", localAddr.IP)
	uri := StrIPlocal + port
    return uri
}

func GenerateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce")
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func GetProfileData(r *http.Request) map[string]string {


	m := make(map[string]string)

	session, err := SessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func IsAuthenticated(r *http.Request) bool {
	session, err := SessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func HaveDASVID() bool {

	if os.Getenv("DASVIDToken") == "" {
		return false
	}

	return true
}

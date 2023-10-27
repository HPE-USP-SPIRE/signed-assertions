package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/IDMode/Assertingwl-mTLS/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
)

func IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	defer timeTrack(time.Now(), "Introspect endpoint")
	var zkp string
	var keyjson []byte

	// Retrieve claims and validate token exp before signature validation
	datoken := r.FormValue("DASVID")

	// // Open dasvid cache file
	datafile, err := ioutil.ReadFile("./data/dasvid.data")
	if err != nil {
		log.Fatalln(err)
	}

	// // Iterate over lines looking for DASVID token
	lines := strings.Split(string(datafile), "\n")
	Filetemp := models.FileContents{}
	for i := range lines {

		json.Unmarshal([]byte(lines[i]), &Filetemp)
		if err != nil {
			log.Printf("Key %d not match...", i)
		}

		if Filetemp.DASVIDToken == datoken {
			log.Println("DASVID token identified!")

			parts := strings.Split(Filetemp.OauthToken, ".")
			message := []byte(strings.Join(parts[0:2], "."))

			if Filetemp.ZKP == "" {
				log.Println("No ZKP identified! Generating one...")

				zkp = dasvid.GenZKPproof(Filetemp.OauthToken)
				if zkp == "" {
					log.Println("Error generating ZKP proof")
				}

				pubkey := dasvid.RetrieveJWKSPublicKey("./keys/oauth.json")

				// Verify token signature using extracted Public key
				for i := 0; i < len(pubkey.Keys); i++ {

					err := dasvid.VerifySignature(Filetemp.OauthToken, pubkey.Keys[i])
					if err != nil {
						log.Printf("Key %d not match...", i)
					} else {
						log.Printf("Key found!")
						keyjson, err = json.Marshal(pubkey.Keys[i])
						if err != nil {
							fmt.Println("error:", err)
							return
						}
						log.Printf("Generated pubkey to future use: %s", string(keyjson))

						Filetemp = models.FileContents{
							OauthToken:  Filetemp.OauthToken,
							DASVIDToken: datoken,
							Msg:         message,
							ZKP:         zkp,
							PubKey:      keyjson,
						}

						tmpstr, _ := json.Marshal(Filetemp)
						lines[i] = string(tmpstr)
						datafile = []byte(strings.Join(lines, "\n"))
						err := ioutil.WriteFile("./data/dasvid.data", datafile, 0644)
						if err != nil {
							log.Fatalln(err)
						}

						Filetemp = models.FileContents{
							Msg:    message,
							ZKP:    zkp,
							PubKey: keyjson,
						}
						json.NewEncoder(w).Encode(Filetemp)
						return
					}
				}
			} else {
				log.Println("Previous ZKP identified!")
				zkp = Filetemp.ZKP

				Filetemp = models.FileContents{
					Msg:    message,
					ZKP:    Filetemp.ZKP,
					PubKey: Filetemp.PubKey,
				}
			}
			json.NewEncoder(w).Encode(Filetemp)
			return
		}
	}
	json.NewEncoder(w).Encode("DASVID not found")
}

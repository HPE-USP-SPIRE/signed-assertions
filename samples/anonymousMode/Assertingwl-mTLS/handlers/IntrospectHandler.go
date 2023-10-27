package handlers

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hpe-usp-spire/signed-assertions/anonymousMode/Assertingwl-mTLS/models"
	dasvid "github.com/hpe-usp-spire/signed-assertions/poclib/svid"
)

func IntrospectHandler(w http.ResponseWriter, r *http.Request) {

	var fileTemp models.FileContents
	
	defer timeTrack(time.Now(), "Introspect endpoint")
	var zkp string

	// Retrieve claims and validate token exp before signature validation
	datoken := r.FormValue("DASVID")

	// // Open dasvid cache file
	datafile, err := ioutil.ReadFile("./data/dasvid.data")
	if err != nil {
		log.Fatalln(err)
	}

	// // Iterate over lines looking for DASVID token
	lines := strings.Split(string(datafile), "\n")
	for i := range lines {

		json.Unmarshal([]byte(lines[i]), &fileTemp)
		if err != nil {
			log.Printf("error:", err)
		}

		if fileTemp.DASVIDToken == datoken {
			log.Println("DASVID token identified!")

			parts := strings.Split(fileTemp.OauthToken, ".")
			message := []byte(strings.Join(parts[0:2], "."))

			if fileTemp.ZKP == "" {
				log.Println("No ZKP identified! Generating one...")

				zkp = dasvid.GenZKPproof(fileTemp.OauthToken)
				if zkp == "" {
					log.Println("Error generating ZKP proof")
				}

				fileTemp = models.FileContents{
					OauthToken:		fileTemp.OauthToken,
					DASVIDToken:	datoken,
					Msg:			message,
					ZKP:			zkp,
				}

				tmpstr, _ := json.Marshal(fileTemp)
				lines[i] = string(tmpstr)
				datafile = []byte(strings.Join(lines, "\n"))
				err := ioutil.WriteFile("./data/dasvid.data", datafile, 0644)
				if err != nil {
					log.Fatalln(err)
				}

				fileTemp = models.FileContents{
					Msg:    message,
					ZKP:    zkp,
				}
				// json.NewEncoder(w).Encode(fileTemp)
				// return
			} else {
				log.Println("Previous ZKP identified!")
				zkp = fileTemp.ZKP

				fileTemp = models.FileContents{
					Msg:	message,
					ZKP:	fileTemp.ZKP,
				}
			}
			json.NewEncoder(w).Encode(fileTemp)
			return
		}
	}
	json.NewEncoder(w).Encode("DASVID not found")
}

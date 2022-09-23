package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type kidKeydata struct {
	// keydata	[]map[string]interface{}	`json:"keydata"`
	Kid							string `json:kid",omitempty"`
	Alg							string `json:alg",omitempty"`
	Pkey						string `json:pkey",omitempty"`
	Exp							int64 `json:exp",omitempty"`

	// Kid:"KEY ID",
	// "alg":"ALGORITHM TYPE",
	// "pkey":"PUBLIC KEY",
	// "exp":"Expiration",
}

var Keys []kidKeydata

func homeLink(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Running!")
}

func addKey(w http.ResponseWriter, r *http.Request) {

	// received structure:
	// {
		//		"kid"	:"KEYID",
		// 		"alg":"ALGORITHM TYPE",
		// 		"pkey":"PUBLIC KEY1",
		// 		"exp":"Expiration",
	//	}

	// How it is stored:
	// [
		// {
			//		"kid"	:"KEYID",
			// 		"alg":"ALGORITHM TYPE",
			// 		"pkey":"PUBLIC KEY1",
			// 		"exp":"Expiration",
		//	}
		// {
			//		"kid"	:"KEYID2",
			// 		"alg":"ALGORITHM TYPE",
			// 		"pkey":"PUBLIC KEY2",
			// 		"exp":"Expiration",
	//	}
	// ]

	var newKey kidKeydata
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(w, "Missing keydata!")
	}
	
	json.Unmarshal(reqBody, &newKey)
	// fmt.Printf("Received key: %s\n\n", newKey.Kid)
	// fmt.Printf("Received key data: %v\n\n", newKey)

	Keys = append(Keys, newKey)
	fmt.Printf("Key added: %v\n\n", newKey)
	json.NewEncoder(w).Encode(newKey)
}

func getOneKey(w http.ResponseWriter, r *http.Request) {
	keyID := mux.Vars(r)["kid"]

	for _, singleKey := range Keys {
		if singleKey.Kid == keyID {
			fmt.Printf("Found kid: %s\n\n", singleKey.Kid)
			json.NewEncoder(w).Encode(singleKey)
		}
	}
}

func getAllKeys(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(Keys)
}

// func updateKey(w http.ResponseWriter, r *http.Request) {
// 	keyID := mux.Vars(r)["kid"]
// 	var updatedKey metadata

// 	reqBody, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		fmt.Fprintf(w, "Kindly enter data with the metadata title and description only in order to update")
// 	}
// 	json.Unmarshal(reqBody, &updatedKey)

// 	for i, singleKey := range Keys {
// 		if singleKey.Spiffeid == keyID {
// 			singleKey.Bioma = updatedKey.Bioma
// 			singleKey.Area = updatedKey.Area
// 			singleKey.Localizacao = updatedKey.Localizacao
// 			singleKey.Status = updatedKey.Status
// 			Keys = append(Keys[:i], singleKey)
// 			json.NewEncoder(w).Encode(singleKey)
// 		}
// 	}
// }

// func deleteKey(w http.ResponseWriter, r *http.Request) {
// 	keyID := mux.Vars(r)["kid"]

// 	for i, singleKey := range Keys {
// 		if singleKey.TokenId == keyID {
// 			Keys = append(Keys[:i], Keys[i+1:]...)
// 			fmt.Fprintf(w, "The metadata with ID %v has been deleted successfully", keyID)
// 		}
// 	}
// }

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", homeLink)
	router.HandleFunc("/addkey", addKey).Methods("POST")
	router.HandleFunc("/keys", getAllKeys).Methods("GET")
	router.HandleFunc("/key/{kid}", getOneKey).Methods("GET")
	// router.HandleFunc("/Keys/{id}", updateKey).Methods("PATCH")
	// router.HandleFunc("/Keys/{id}", deleteKey).Methods("DELETE")
	log.Fatal(http.ListenAndServe(":8888", router))
}
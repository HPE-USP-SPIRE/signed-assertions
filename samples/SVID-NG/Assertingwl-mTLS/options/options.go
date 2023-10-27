package options

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/Assertingwl-mTLS/data"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/options"
)

// InitOptions initializes the options
func InitOptions() (*options.Options, error) {
	log.Print("init options local")
	// init service options
	options := options.NewOptions()
	if err := json.Unmarshal(data.DefaultOptions, options); err != nil {
		return nil, fmt.Errorf("Options initialization unmarshal error: %v", err)
	}

	return options, nil

}

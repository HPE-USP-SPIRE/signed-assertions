package global

import (
	"log"

	api "github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/global"
	alOps "github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/options"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/m-tier/options"
)

var Options *alOps.Options

func init() {
	log.Print("global init")
	// api-libs/options/options.go
	options, err := options.InitOptions()
	if err != nil {
		log.Fatal("Options init errored: ", err.Error())
	}

	Options = options
}

func InitGlobals() {
	log.Print("init global")

	// api-libs/global.go
	api.InitGlobals(Options)

}

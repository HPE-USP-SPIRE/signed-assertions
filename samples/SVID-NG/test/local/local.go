package local

import (
	"log"

	api "github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/global"
	alOps "github.com/hpe-usp-spire/signed-assertions/SVID-NG/api-libs/options"
	"github.com/hpe-usp-spire/signed-assertions/SVID-NG/test/options"
)

var Options *alOps.Options

func init() {
	log.Print("global init")

	options, err := options.InitOptions()
	if err != nil {
		log.Fatal("Options init errored: ", err.Error())
	}

	Options = options
}

func InitGlobals() {
	log.Print("init global")
	api.InitGlobals(Options)
}

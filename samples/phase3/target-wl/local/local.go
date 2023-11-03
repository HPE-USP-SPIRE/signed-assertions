package local

import (
	"log"

	api "github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/global"
	alOps "github.com/hpe-usp-spire/signed-assertions/phase3/api-libs/options"
	"github.com/hpe-usp-spire/signed-assertions/phase3/target-wl/options"
)

var Options *alOps.Options

func init() {
	log.Print("local init")

	options, err := options.InitOptions()
	if err != nil {
		log.Fatal("Options init errored: ", err.Error())
	}

	Options = options
}

func InitGlobals() {
	log.Print("init local")
	api.InitGlobals(Options)

}


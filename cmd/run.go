package main

import (
	"flag"

	restAPI "github.com/iasthc/hsuan-fuzz/pkg/rest-api"
)

var (
	openAPIPath string
	inputPath   string
	strictMode  bool
	guideMode   bool
)

func init() {

	flag.StringVar(&openAPIPath, "o", ".", "location of `oenapi` specification ")
	flag.StringVar(&inputPath, "c", ".", "location to save `corpus`")
	flag.BoolVar(&strictMode, "s", false, "`strict` mode")
	flag.BoolVar(&guideMode, "g", false, "`guided` mode")

}

func main() {
	flag.Parse()
	x, err := restAPI.New(openAPIPath, inputPath, true, strictMode)
	if err != nil {
		panic(err)
	}
	x.Fuzz(guideMode)
}

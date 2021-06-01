package main

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	restAPI "github.com/iasthc/hsuan-fuzz/pkg/rest-api"
)

func main() {

	openAPIsPath := ""
	inputPath := ""
	guideMode := true
	strictMode := true

	err := filepath.Walk(openAPIsPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasPrefix(strings.ToLower(info.Name()), "openapi.") {

			x, err := restAPI.New(path, inputPath, true, strictMode)
			if err != nil {

				f, err := os.OpenFile("err.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Println(err)
				}
				defer f.Close()

				if _, err := f.WriteString(path + "\n"); err != nil {
					log.Println(err)
				}

			} else {

				x.Fuzz(guideMode)

			}
		}

		return nil

	})

	if err != nil {
		log.Println(err)
		return
	}

}

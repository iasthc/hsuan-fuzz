package hsuanfuzz

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/valyala/fastjson"
	"gopkg.in/yaml.v2"
)

// Token is used to manually enter service authorization information.
type Token struct {
	URL         string      `yaml:"url"`
	Method      string      `yaml:"method"`
	Key         string      `yaml:"key"`
	Bearer      string      `yaml:"bearer"` // is empty when initial
	ContentType string      `yaml:"type"`
	Body        interface{} `yaml:"body"`
	Hardcode    bool        `yaml:"hardcode"`
	In          string      `yaml:"in"`
}

// GetToken obtains the authorization key based on the input information.
func GetToken(t Token, print bool) string {

	/* For https */
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// hardcode
	if t.Hardcode {
		return t.Bearer
	}

	b, err := yaml.Marshal(t.Body)
	if err != nil {
		panic(err)
	}

	body := string(b)

	if strings.HasPrefix(body, "'") {
		body = body[1 : len(body)-2]
	}

	req, err := http.NewRequest(t.Method, t.URL, strings.NewReader(body))
	if err != nil {
		panic(err)
	}

	if t.ContentType != "" {
		req.Header.Set("Content-Type", t.ContentType)
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		panic("Invalid log in, code: " + strconv.Itoa(res.StatusCode))
	}

	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	// fastjson keys
	keys := []string{}
	key := ""
	for _, c := range t.Key {

		if c == '{' {

			keys = append(keys, key)
			key = ""

		} else if c == '[' {

			keys = append(keys, key)
			key = ""
			key += "0"

		} else if c == ']' || c == '}' {

			if len(key) > 0 {
				keys = append(keys, key)
				key = ""
			}

		} else {

			key += string(c)

		}

	}

	/* Customized token info */
	v := fastjson.MustParseBytes(b).Get(keys...)

	/* SPREE: access_token */
	/* REALWORLD: user{token} */
	bearer := string(v.GetStringBytes())

	if bearer == "" {

		/* MAGENTO: w/o key */
		bearer = strings.ReplaceAll(string(b), "\"", "")

	}

	if print {
		fmt.Println(bearer)
	}

	return bearer

}

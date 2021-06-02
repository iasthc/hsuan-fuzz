package hsuanfuzz

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/iasthc/hsuan-fuzz/internal/base"
	"google.golang.org/protobuf/types/known/structpb"
)

// ResponseInfo is used to carry request and response information.
type ResponseInfo struct {
	request *base.Node
	Code    int
	Type    string
	Body    string
}

// SendRequest uses our grammar to send the request.
func (x *HsuanFuzz) SendRequest(node *base.Node, decode bool) *ResponseInfo {

	// time.Sleep(100 * time.Millisecond)

	u := url.URL{}
	u.Path = node.Path
	query := u.Query()
	header := http.Header{}
	body := ""

	for _, request := range node.Requests {

		if request.Type == openapi3.ParameterInPath || request.Type == openapi3.ParameterInQuery || request.Type == openapi3.ParameterInHeader {

			for k, v := range request.Value.GetFields() {

				value := x.getStringValue(v, decode, true)

				// Set values
				if request.Type == openapi3.ParameterInPath {

					u.Path = strings.ReplaceAll(u.Path, ("{" + k + "}"), url.PathEscape(value))

				} else if request.Type == openapi3.ParameterInQuery {

					query.Set(k, url.QueryEscape(value))

				} else if request.Type == openapi3.ParameterInHeader {

					header.Set(k, value)

				}

			}

		} else if strings.Contains(strings.ToLower(request.Type), "json") {

			header.Set("Content-Type", request.Type)

			value, err := structpb.NewValue(request.Value.AsMap())
			if err != nil {
				panic(err)
			}
			body = x.getStringValue(value, decode, true)

			_, vs := getKeyValue("", value)
			for _, v := range vs {

				switch v.GetKind().(type) {

				case *structpb.Value_StringValue:

					decoded, err := base64.StdEncoding.DecodeString(v.GetStringValue())
					if err == nil {
						body = strings.ReplaceAll(body, v.GetStringValue(), string(decoded))
					}

				}

			}

		} else {

			panic("Invalid: request type " + request.Type)

		}

	}

	/* Security */
	if x.Token.Bearer != "" {
		if x.Token.In == "query" {
			query.Set("Authorization", x.Token.Bearer)
		} else {
			// header.Set("Authorization", "Token "+x.Token.Bearer)
			header.Set("Authorization", "Bearer "+x.Token.Bearer)
		}
	}

	// log.Println((x.server + url.PathEscape(u.Path) + "?" + query.Encode()))
	// log.Println(strings.NewReader(body))
	// p := url.PathEscape(x.server + u.Path)
	// p = strings.ReplaceAll(p, "%2F", "/")
	/* New Request */
	req, err := http.NewRequest(node.Method, (x.server + u.Path + "?" + query.Encode()), strings.NewReader(body))
	if err != nil {
		log.Println(err)
		if x.strictMode {
			return &ResponseInfo{
				request: node,
				Code:    599,
				Body:    err.Error(),
			}
		}
	}

	// Set header
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}

	/* Response */
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return &ResponseInfo{
			request: node,
			Code:    599,
			Body:    err.Error(),
		}
	}
	defer res.Body.Close()

	resBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	resBody := string(resBytes)

	/* Save response to fuzzer */
	if res.StatusCode/100 == 2 {
		if strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "json") {
			if (*x.groupInfo)[node.Group] == nil {
				(*x.groupInfo)[node.Group] = make(map[string]string)
			}

			(*x.groupInfo)[node.Group][node.Path] = string(resBytes)
		}
	}

	return &ResponseInfo{
		request: node,
		Code:    res.StatusCode,
		Type:    res.Header.Get("Content-Type"),
		Body:    resBody,
	}
}

package hsuanfuzz

import (
	"net/http"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/iasthc/hsuan-fuzz/internal/base"
	"github.com/iasthc/hsuan-fuzz/internal/example"
	"google.golang.org/protobuf/types/known/structpb"
)

func (x *HsuanFuzz) generateGrammar() {

	// Get path order
	orders := map[string][]string{}
	for path, info := range x.dependency.Paths {

		orders[path] = append(x.getOperationFlows(info), path)

	}

	if !x.strictMode {
		for _, p := range x.sortedPaths {
			orders[p] = []string{p}
		}
	}

	// Use path order to get operations
	nodes := []*base.Node{}
	group := uint32(1)
	for _, p := range x.sortedPaths {

		dels := []*base.Node{}
		for _, path := range orders[p] {
			for _, operation := range operationsOrder {
				if operation == http.MethodDelete {
					dels = append(x.newNode(group, path, operation), dels...)
					continue
				}
				nodes = append(nodes, x.newNode(group, path, operation)...)
			}
		}
		nodes = append(nodes, dels...)
		group++

	}

	x.grammar = &base.Info{Nodes: nodes}

}

func (x *HsuanFuzz) newNode(group uint32, path string, method string) []*base.Node {

	operation := x.openAPI.Paths[path].GetOperation(method)
	if operation == nil {
		return nil
	}

	// if operation.Deprecated || operation.Servers != nil || operation.Callbacks != nil || operation.ExternalDocs != nil {
	// 	fmt.Println(operation.Deprecated, operation.Servers, operation.Callbacks, operation.ExternalDocs)
	// 	panic("Invalid operation.")
	// }

	// Priority of operation parameters is greater than pathitem.
	parameterRefs := map[string]*openapi3.ParameterRef{}
	for _, parameterRef := range append(x.openAPI.Paths[path].Parameters, operation.Parameters...) {
		parameterRefs[parameterRef.Value.Name] = parameterRef
	}

	requests := x.getRequestParameters(parameterRefs, operation.RequestBody)

	exclude := 0
	for _, code := range excludeCodes {
		if _, ok := operation.Responses[code]; ok {
			exclude++
		}
	}

	nodes := []*base.Node{}
	for i := 0; i < (len(operation.Responses) - exclude); i++ {
		nodes = append(nodes, &base.Node{Group: group, Path: path, Method: method, Requests: requests})
	}

	return nodes

}

func (x *HsuanFuzz) getRequestParameters(ps map[string]*openapi3.ParameterRef, rb *openapi3.RequestBodyRef) []*base.Request {

	requests := []*base.Request{}

	sorted := []string{}
	for path := range ps {
		sorted = append(sorted, path)
	}
	sort.Strings(sorted)

	for _, c := range sorted {

		ref := ps[c]

		// bool, float64, int, string
		ex, err := example.GetParameterExample(example.ModeRequest, ref.Value)
		if err != nil {
			panic(err)
		}

		// BoolValue, NumberValue, StringValue
		v, err := structpb.NewValue(ex)
		if err != nil {
			panic(err)
		}

		// base64 encode
		if v.GetStringValue() != "" {
			v, err = structpb.NewValue([]byte(v.GetStringValue()))
			if err != nil {
				panic(err)
			}
		}

		// StructValue
		value, err := structpb.NewStruct(map[string]interface{}{ref.Value.Name: v.AsInterface()})
		if err != nil {
			panic(err)
		}

		requests = append(requests, &base.Request{Type: ref.Value.In, Value: value})

	}

	if rb != nil {

		for mt, ref := range rb.Value.Content {

			if strings.Contains(strings.ToLower(mt), "json") {

				// map[string]interface{}
				ex, err := example.GetBodyExample(example.ModeRequest, ref)
				if err != nil {
					if x.strictMode {
						panic(err)
					}
				}

				// StructValue
				v, err := structpb.NewValue(ex)
				if err != nil {
					panic(err)
				}

				// base64 encode
				svs := []*structpb.Value{}
				for a, b := range v.GetStructValue().GetFields() {
					_, sv := getKeyValue(a, b)
					svs = append(svs, sv...)
				}
				for _, sv := range svs {
					if sv.GetStringValue() != "" {
						nv, err := structpb.NewValue([]byte(sv.GetStringValue()))
						if err != nil {
							panic(err)
						}
						*sv = *structpb.NewStringValue(nv.GetStringValue())
					}
				}

				requests = append(requests, &base.Request{Type: mt, Value: v.GetStructValue()})

			}

		}

	}

	return requests
}

func (x *HsuanFuzz) getOperationFlows(info *DependencyInfo) []string {

	// Incorrect dependency will lead to infinite loop or panic.
	// e.g. cycle or non-existent path

	res := []string{}

	for _, item := range info.Items {

		if x.strictMode && item.Source.Path != "x" {

			res = append(res, x.getOperationFlows(x.dependency.Paths[item.Source.Path])...)
			res = append(res, item.Source.Path)

		}

	}

	return res
}

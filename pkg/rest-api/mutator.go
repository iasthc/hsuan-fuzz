package hsuanfuzz

import (
	"encoding/base64"
	"math/rand"
	"strconv"
	"time"

	gofuzz "github.com/iasthc/hsuan-fuzz/internal/go-fuzz"
	"github.com/valyala/fastjson"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func (x *HsuanFuzz) getStringValue(value *structpb.Value, decode, appendList bool) string {

	v := ""

	switch value.GetKind().(type) {

	case *structpb.Value_BoolValue:

		v = strconv.FormatBool(value.GetBoolValue())

	case *structpb.Value_NumberValue:

		v = strconv.FormatFloat(value.GetNumberValue(), 'f', -1, 64)

	case *structpb.Value_StringValue:

		if decode {

			data, err := base64.StdEncoding.DecodeString(value.GetStringValue())
			if err != nil {

				v = value.GetStringValue()

			} else {

				v = string(data)

			}

		} else {

			// for v4 reproduce
			v = value.GetStringValue()

		}

	case *structpb.Value_ListValue:

		vs := value.GetListValue().Values

		if appendList {

			for i, s := range vs {

				v += x.getStringValue(s, decode, appendList)

				if i != len(vs)-1 {
					v += ", "
				}

			}

		} else {

			if len(vs) > 0 {
				v = x.getStringValue(vs[0], decode, appendList)
			}

		}

	case *structpb.Value_StructValue:

		encoded, err := protojson.Marshal(value)
		if err != nil {
			panic(err)
		}
		v = string(encoded)

	case *structpb.Value_NullValue:

		// Already deleted

	default:

		if x.strictMode {
			panic(value.GetKind())
		}

	}

	return v
}

func getKeyValue(k string, x *structpb.Value) ([]string, []*structpb.Value) {

	ks := []string{}
	vs := []*structpb.Value{}

	switch x.GetKind().(type) {

	case *structpb.Value_NullValue, *structpb.Value_NumberValue, *structpb.Value_StringValue, *structpb.Value_BoolValue:

		ks = append(ks, k)
		vs = append(vs, x)

	case *structpb.Value_StructValue:

		for a, b := range x.GetStructValue().GetFields() {

			_ks, _vs := getKeyValue(a, b)
			ks = append(ks, _ks...)
			vs = append(vs, _vs...)

		}

	case *structpb.Value_ListValue:

		for _, c := range x.GetListValue().GetValues() {

			switch c.GetKind().(type) {

			case *structpb.Value_NullValue, *structpb.Value_NumberValue, *structpb.Value_StringValue, *structpb.Value_BoolValue:

				ks = append(ks, k)
				vs = append(vs, x)

			case *structpb.Value_StructValue:

				for a, b := range c.GetStructValue().GetFields() {

					_ks, _vs := getKeyValue(a, b)
					ks = append(ks, _ks...)
					vs = append(vs, _vs...)

				}

			case *structpb.Value_ListValue:

				for _, d := range c.GetListValue().GetValues() {

					switch d.GetKind().(type) {

					case *structpb.Value_NullValue, *structpb.Value_NumberValue, *structpb.Value_StringValue, *structpb.Value_BoolValue:

						ks = append(ks, k)
						vs = append(vs, x)

					case *structpb.Value_StructValue:

						for a, b := range d.GetStructValue().GetFields() {

							_ks, _vs := getKeyValue(a, b)
							ks = append(ks, _ks...)
							vs = append(vs, _vs...)

						}

					case *structpb.Value_ListValue:

						panic("Invalid: recursive list " + k)

					}

				}

			}

		}

	}

	return ks, vs
}

func (x *HsuanFuzz) isRelated(path string, key string) bool {

	if x.strictMode {

		for _, item := range x.dependency.Paths[path].Items {
			if item.Key == key {
				return true
			}
		}

	}

	return false
}

func (x *HsuanFuzz) adoptStrategies() {

	for _, node := range x.grammar.Nodes {

		values := []*structpb.Value{}
		keys := []string{}

		// Get all request values
		for _, request := range node.Requests {

			for k, v := range request.Value.GetFields() {

				ks, vs := getKeyValue(k, v)
				keys = append(keys, ks...)
				values = append(values, vs...)

			}

		}

		// Choose two parameters to modify
		selected := map[int]bool{}

		if len(values) >= 2 {

			record := -1

			for len(selected) < 2 {

				rand.Seed(time.Now().UnixNano())
				random := rand.Intn(len(values))

				if record == random {
					continue
				}

				selected[random] = true

			}

		}

		// Execute our strategy
		for i, value := range values {

			// Set dependencies values
			if x.isRelated(node.Path, keys[i]) {

				for _, item := range x.dependency.Paths[node.Path].Items {

					// Get id from the previous response
					if body, ok := (*x.groupInfo)[node.Group][item.Source.Path]; ok {

						// Convert dependency.yml item.Source.Key to fastjson keys
						keys := []string{}
						key := ""
						for _, c := range item.Source.Key {

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

						// Get id from JSON and set value
						valJSON := fastjson.MustParse(body).Get(keys...)

						switch value.GetKind().(type) {

						case *structpb.Value_NumberValue:
							if int(valJSON.GetFloat64()) > valJSON.GetInt() {

								*value = *structpb.NewNumberValue(valJSON.GetFloat64())

							} else {

								*value = *structpb.NewNumberValue(float64(valJSON.GetInt()))

							}

						case *structpb.Value_StringValue:

							v, err := structpb.NewValue(valJSON.GetStringBytes())
							if err != nil {
								panic(err)
							}

							*value = *structpb.NewStringValue(v.GetStringValue())

						}

					}

				}

			}

			// If it is not being selected to the value
			if len(values) >= 2 {
				if _, ok := selected[i]; !ok {
					continue
				}
			}

			// Get value of string type
			v := x.getStringValue(value, true, false)

			// Determine how to modify
			rand.Seed(time.Now().UnixNano())
			random := rand.Intn(5)

			if random == 0 {

				//Delete
				deleted := false
				for _, request := range node.Requests {

					for k := range request.Value.GetFields() {

						if k == keys[i] {
							delete(request.Value.GetFields(), k)
							deleted = true
							break
						}

					}

					if deleted {
						break
					}

				}

			} else if random == 1 {

				//NULL?
				//Change type
				rand.Seed(time.Now().UnixNano())
				random = rand.Intn(2)

				switch value.GetKind().(type) {

				case *structpb.Value_NumberValue:
					if random == 0 {
						if len(v) > 0 {
							*value = *structpb.NewBoolValue((v[0] % 2) == 0)
						} else {
							*value = *structpb.NewBoolValue(false)
						}
					} else {
						if len(v) > 0 {
							*value = *structpb.NewNumberValue(float64(v[0]))
						} else {
							*value = *structpb.NewNumberValue(0)
						}
					}

				case *structpb.Value_StringValue:
					if random == 0 {
						if len(v) > 0 {
							*value = *structpb.NewNumberValue(float64(v[0]))
						} else {
							*value = *structpb.NewNumberValue(0)
						}
					} else {
						if len(v) > 0 {
							*value = *structpb.NewBoolValue((v[0] % 2) == 0)
						} else {
							*value = *structpb.NewBoolValue(false)
						}
					}

				case *structpb.Value_BoolValue:
					if random == 0 {
						v, err := structpb.NewValue([]byte(v))
						if err != nil {
							panic(err)
						}

						*value = *structpb.NewStringValue(v.GetStringValue())
					} else {
						if len(v) > 0 {
							*value = *structpb.NewNumberValue(float64(v[0]))
						} else {
							*value = *structpb.NewNumberValue(0)
						}
					}
				}

			} else {

				//Mutate
				mu := gofuzz.NewMutator()
				mv := mu.Mutate([]byte(v))

				switch value.GetKind().(type) {

				case *structpb.Value_BoolValue:

					if len(string(mv)) > 0 {
						*value = *structpb.NewBoolValue((string(mv)[0] % 2) == 0)
					} else {
						*value = *structpb.NewBoolValue(false)
					}

				case *structpb.Value_NumberValue:

					if len(string(mv)) > 0 {
						*value = *structpb.NewNumberValue(float64(string(mv)[0]))
					} else {
						*value = *structpb.NewNumberValue(0)
					}

				case *structpb.Value_StringValue:

					v, err := structpb.NewValue(mv)
					if err != nil {
						panic(err)
					}

					*value = *structpb.NewStringValue(v.GetStringValue())

				}

			}

		}

	}

}

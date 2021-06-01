package hsuanfuzz

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/iasthc/hsuan-fuzz/internal/example"
)

var excludeCodes = []string{"default", "401", "403", "500"}
var operationsOrder = []string{http.MethodOptions, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodGet, http.MethodDelete, http.MethodTrace}

type Criteria struct {
	Input  InputCriteria
	Output OutputCriteria
}

type InputCriteria struct {
	Types      map[string]int
	Parameters map[string]int
}

type OutputCriteria struct {
	Types       map[string]int
	CodeClasses map[int]int
	Codes       map[int]int
	Properties  map[string]int
}

func getJSONKeys(v interface{}) []string {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}

	keys := []string{}
	reJSON := regexp.MustCompile(`"([^"]+?)"\s*:`)
	for _, r := range reJSON.FindAllString(string(encoded), -1) {
		keys = append(keys, strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(r, "\"", ""), ":", ""), "\\", ""))
	}

	return keys
}

func isWithinThresholds(a int, b int) bool {
	if b == 0 {
		return true
	}
	threshold := 0.5 // TODO TCM 有寫嗎？
	return float64(float64(a)/float64(b)) >= threshold
}

func (x *HsuanFuzz) getCoverageLevels(mapInfos map[uint32][]*ResponseInfo) Coverage {
	/* exclude */
	// exclusionCodes := []int{401, 403, 500}
	// exclusionTypes := []string{"", "xml", "html"}

	// map[Path][Method]Criteria
	goals := map[string]map[string]Criteria{}
	seeds := map[string]map[string]Criteria{}
	tmpLevels := map[string]map[string]int{}

	for path := range x.openAPI.Paths {

		goals[path] = map[string]Criteria{}

		for method, operation := range x.openAPI.Paths[path].Operations() {

			// Request
			ic := InputCriteria{Types: map[string]int{}, Parameters: map[string]int{}}

			if operation.RequestBody == nil {

				// Request Parameters
				for _, parameter := range append(x.openAPI.Paths[path].Parameters, operation.Parameters...) {

					ic.Parameters[parameter.Value.Name]++

				}

			} else {

				for mediaType, content := range operation.RequestBody.Value.Content {

					// Request Types
					// JSON only
					if strings.Contains(strings.ToLower(mediaType), "json") {
						ic.Types["json"]++
					}

					// Request Parameters
					ex, err := example.GetBodyExample(example.ModeRequest, content)
					if err != nil {
						if x.strictMode {
							panic(err)
						}
					}

					for _, key := range getJSONKeys(ex) {

						ic.Parameters[key]++

					}

				}

			}

			// Response
			oc := OutputCriteria{Types: map[string]int{}, CodeClasses: map[int]int{}, Codes: map[int]int{}, Properties: map[string]int{}}

			for code, response := range operation.Responses {

				exclude := false

				for _, code := range excludeCodes {
					if _, ok := operation.Responses[code]; ok {
						exclude = true
						break
					}
				}

				if exclude {
					continue
				}

				// Response Code Classes and Codes
				c, err := strconv.Atoi(code)
				if err != nil {
					if x.strictMode {
						panic(err)
					}
				}

				oc.CodeClasses[c/100]++
				oc.Codes[c]++

				for mediaType, content := range response.Value.Content {

					// Response Types
					// JSON only
					if strings.Contains(strings.ToLower(mediaType), "json") {
						oc.Types["json"]++
					}

					// Response Properties
					ex, err := example.GetResponseExample(example.ModeResponse, content)
					if err != nil {
						if x.strictMode {
							panic(err)
						}
					}

					for _, key := range getJSONKeys(ex) {

						oc.Properties[key]++

					}

				}

			}

			goals[path][method] = Criteria{Input: ic, Output: oc}

		}

	}

	// Response Information
	for _, infos := range mapInfos {

		for _, info := range infos {

			// Request
			ic := InputCriteria{Types: map[string]int{}, Parameters: map[string]int{}}

			pbKeys := []string{}
			for _, request := range info.request.Requests {

				for k, v := range request.Value.GetFields() {

					ks, _ := getKeyValue(k, v)
					pbKeys = append(pbKeys, ks...)

				}

				// Request Types
				// JSON only
				if strings.Contains(strings.ToLower(request.Type), "json") {
					ic.Types["json"]++
				}

			}

			// Request Parameters
			for _, key := range pbKeys {
				ic.Parameters[key]++
			}

			// Response
			oc := OutputCriteria{Types: map[string]int{}, CodeClasses: map[int]int{}, Codes: map[int]int{}, Properties: map[string]int{}}

			// Response Code Classes and Codes
			oc.CodeClasses[info.Code/100]++
			oc.Codes[info.Code]++

			// Response Types
			// JSON only
			if strings.Contains(strings.ToLower(info.Type), "json") {
				oc.Types["json"]++
			}

			// Response Properties
			for _, key := range getJSONKeys(info.Body) {
				oc.Properties[key]++
			}

			if seeds[info.request.Path] == nil {
				seeds[info.request.Path] = map[string]Criteria{}
			}

			// Merge two maps
			if c, ok := seeds[info.request.Path][info.request.Method]; ok {

				for a := range c.Input.Parameters {
					ic.Parameters[a]++
				}

				for a := range c.Input.Types {
					ic.Types[a]++
				}

				for a := range c.Output.CodeClasses {
					oc.CodeClasses[a]++
				}

				for a := range c.Output.Codes {
					oc.Codes[a]++
				}

				for a := range c.Output.Types {
					oc.Types[a]++
				}

				for a := range c.Output.Properties {
					oc.Properties[a]++
				}

			}

			seeds[info.request.Path][info.request.Method] = Criteria{Input: ic, Output: oc}

		}

	}

	// Generate Levels by operations (methods).
	for _, path := range x.sortedPaths {

		tmpLevels[path] = map[string]int{}

		for _, method := range operationsOrder {

			if _, ok := goals[path][method]; !ok {
				continue
			}

			goal := goals[path][method]
			seed := seeds[path][method]

			next := true

			/* Level 1: 包含所有 path */
			/* Level 2: 包含所有 operation */
			/* Level 3: 包含所有 content-type */
			// goal xml json
			// seed xml json html
			level := 0
			for t := range goal.Input.Types {
				if _, ok := seed.Input.Types[t]; !ok {
					level = 2
					next = false
					break
				}
			}

			if next {
				for t := range goal.Output.Types {
					if _, ok := seed.Output.Types[t]; !ok {
						level = 2
						next = false
						break
					}
				}
			}

			/* Parameter coverage: To achieve 100% parameter coverage, all input parameters of every operation must be used at least once. Exercising different combinations of parameters is desirable, but not strictly necessary to achieve 100% of coverage under this criterion.*/
			if next {

				total := 0
				exist := 0

				for t := range goal.Input.Parameters {

					total++

					if _, ok := seed.Input.Parameters[t]; ok {

						exist++

					}

				}

				if !isWithinThresholds(exist, total) {
					level = 3
					next = false
				}

			}

			/* Level 4: 包含部分 parameters, 包含所有 status code classes */
			if next {

				for t := range goal.Output.CodeClasses {

					if t != 3 && t != 5 {

						if _, ok := seed.Output.CodeClasses[t]; !ok {

							level = 3
							next = false
							break

						}

					}

				}

			}

			/* Level 5: 包含部分 parameters, 包含所有 status code */
			if next {

				for t := range goal.Output.Codes {

					if _, ok := seed.Output.Codes[t]; !ok {

						level = 4
						next = false
						break

					}

				}

			}

			/* Level 6: 包含部分 parameters, 包含部分 response body */
			if next {

				total := 0
				exist := 0

				for t := range goal.Output.Properties {

					total++

					if _, ok := seed.Output.Properties[t]; ok {

						exist++

					}

				}

				if !isWithinThresholds(exist, total) {
					level = 5
					next = false
				}

			}

			if next {

				level = 6

			}

			tmpLevels[path][method] = level

			// fmt.Println(level)
			// fmt.Printf("goal: %+v\nseed: %+v\n", goal.Input.Types, seed.Input.Types)
			// fmt.Printf("goal: %+v\nseed: %+v\n", goal.Output.Types, seed.Output.Types)
			// fmt.Printf("goal: %+v\nseed: %+v\n", goal.Input.Parameters, seed.Input.Parameters)
			// fmt.Printf("goal: %+v\nseed: %+v\n", goal.Output.CodeClasses, seed.Output.CodeClasses)
			// fmt.Printf("goal: %+v\nseed: %+v\n", goal.Output.Codes, seed.Output.Codes)
			// fmt.Printf("goal: %+v\nseed: %+v\n", goal.Output.Properties, seed.Output.Properties)
			// fmt.Println()

		}

	}

	cov := Coverage{}

	for _, path := range x.sortedPaths {

		for _, method := range operationsOrder {

			if _, ok := goals[path][method]; !ok {
				continue
			}

			// If the resource is a sub-resource of another one, the creation of the parent resource must be included in the operation flow.
			// Level 7
			if x.strictMode && x.openAPI.Paths[path].GetOperation(http.MethodPost) != nil {

				atLeastOne := false
				for _, flow := range x.dependency.Posts[path].Flows {
					if flow.Path != "" {
						atLeastOne = true
						break
					}
				}

				next := true
				if atLeastOne {
					for _, flow := range x.dependency.Posts[path].Flows {
						if flow.Path != "" {
							if l, ok := tmpLevels[flow.Path][flow.Method]; ok {
								if l < 6 {
									next = false
									break
								}
							} else {
								panic("Invalid: wrong order of sending paths [" + flow.Method + "] " + flow.Path)
							}
						}
					}
				}

				if next {
					tmpLevels[path][method] = 7
				}

			}

			cov.Levels = append(cov.Levels, tmpLevels[path][method])

		}

	}

	if len(cov.Levels) != x.methods {
		panic("Invalid get levels.")
	}

	return cov
}

// func isOverallIncrease(x []int, y []int, print bool) bool {
// 	a := map[int]int{}
// 	for _, level := range x {
// 		a[level]++
// 	}

// 	b := map[int]int{}
// 	for _, level := range y {
// 		b[level]++
// 	}

// 	if print {
// 		log.Println("--------------------------------------------------")
// 		log.Println(fmt.Sprintf("%[1]*s", -50, fmt.Sprintf("%[1]*s", (50+len("Overall"))/2, "Overall")))
// 		log.Println("--------------------------------------------------")
// 		log.Println(a)
// 		log.Println(b)
// 	}

// 	if len(b) == 0 {
// 		return true
// 	}
// 	for i := 7; i > 0; i-- {
// 		if a[i] > b[i] {
// 			return true
// 		} else if a[i] == b[i] {
// 			continue
// 		} else {
// 			return false
// 		}
// 	}
// 	return false
// }

func isIndividualIncrease(a []int, b []int, print bool) (bool, Coverage) {

	flag := false
	for i := 0; i < len(a); i++ {
		if a[i] > b[i] {
			flag = true
		} else {
			a[i] = b[i]
		}
	}
	return flag, Coverage{Levels: a}
}

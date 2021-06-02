package hsuanfuzz

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/iasthc/hsuan-fuzz/internal/base"
	"github.com/iasthc/hsuan-fuzz/internal/example"
	gofuzz "github.com/iasthc/hsuan-fuzz/internal/go-fuzz"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"
)

// OpenAPI 3.0.3
// https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.3.md

// TODO https://github.com/golang/lint
// TODO XML to JSON
// TODO: *openapi3.ExtensionProps
// TODO: Example 不要放進grammar => 直接放這次 send 的 value
// TODO: 當 quicktest 再取 => 暫時不做
// TODO :format "email", "uuid"
// TODO: mutate two location of each path (operations)
// TODO: SET mutant and DEL some parameters
// TODO: Change data type
// TODO: Random 不夠隨機
// TODO: 共二
// TODO: string utf8 bytes ***
// TODO: SEND JSON ONLY

// PathInfo is used to display request information more easily.
type PathInfo struct {
	Paths map[string]*PathInfoMethod `yaml:"paths"`
}

// PathInfoMethod presents methods of the path.
type PathInfoMethod struct {
	Method map[string][]*PathInfoParameter `yaml:"methods"`
}

// PathInfoParameter presents parameters of the path.
type PathInfoParameter struct {
	Name  string      `yaml:"name,omitempty"`
	In    string      `yaml:"in,omitempty"`
	Value interface{} `yaml:"value"`
}

// Dependency is used to manually enter the dependency of the path.
type Dependency struct {
	Count int                        `yaml:"count"`
	Paths map[string]*DependencyInfo `yaml:"paths"`
	Posts map[string]*DependencyPost `yaml:"posts"`
}

// DependencyInfo presents the dependency of the path.
type DependencyInfo struct {
	Items []*DependencyItem `yaml:"items"`
}

// DependencyItem presents the ID and source required by the current path.
type DependencyItem struct {
	Key    string            `yaml:"key"`
	Source *DependencySource `yaml:"source"`
}

// DependencySource presents the source path and the ID field of the response.
type DependencySource struct {
	Path string `yaml:"path"`
	Key  string `yaml:"key"`
}

// DependencyPost is used to define test coverage level 7.
type DependencyPost struct {
	Flows []*DependencyPostItem `yaml:"flows"`
}

// DependencyPostItem presents the required request method and path.
type DependencyPostItem struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// HsuanFuzz is the main structure of fuzzer.
type HsuanFuzz struct {
	openAPI     *openapi3.Swagger
	server      string
	grammar     *base.Info
	dependency  Dependency
	Token       Token
	groupInfo   *map[uint32]map[string]string
	methods     int
	sortedPaths []string
	corpus      *gofuzz.PersistentSet
	crashers    *gofuzz.PersistentSet
	endCov      Coverage
	queue       []gofuzz.Sig
	strictMode  bool
}

// Coverage records the test coverage level of each path.
type Coverage struct {
	Levels []int
}

func (c *Coverage) String() string {
	r := ""
	for _, level := range c.Levels {
		r += strconv.Itoa(level) + " "
	}
	return r
}

// Fuzz is equivalent to the execution of Fuzzer, continuously fuzzing.
func (x *HsuanFuzz) Fuzz(guided bool) error {

	log.Println("==================================================")
	log.Println(fmt.Sprintf("%[1]*s", -50, fmt.Sprintf("%[1]*s", (50+len(x.openAPI.Info.Title))/2, x.openAPI.Info.Title)))
	log.Println("==================================================")
	log.Println(x.server)

	x.queue = []gofuzz.Sig{}
	i := 0
	for {

		// If there is no corpus, generate a grammar and add it
		if len(x.corpus.M) == 0 {

			x.generateGrammar()

			// b, err := protojson.Marshal(x.grammar)
			// if err != nil {
			// 	panic(err)
			// }

			// err = ioutil.WriteFile("./init.json", b, 0644)
			// if (err) != nil {
			// 	panic(err)
			// }

			b, err := proto.Marshal(x.grammar)
			if err != nil {
				panic(err)
			}
			x.corpus.Add(gofuzz.Artifact{Data: b})

		}

		// If the queue is used up, read it from the corpus again
		if len(x.queue) == 0 {

			for sig := range x.corpus.M {
				x.queue = append(x.queue, sig)
			}

		}

		// Dequeue
		seed := x.corpus.M[x.queue[0]]
		x.queue = x.queue[1:]

		info := base.Info{}
		err := proto.Unmarshal(seed.Data, &info)
		if err != nil {
			panic(err)
		}
		x.grammar = &info

		// Modify
		x.adoptStrategies()

		// Get Token
		if x.strictMode {
			x.Token.Bearer = GetToken(x.Token, false)
		}

		// Send requests and save responses
		mapCodes := map[int]int{}
		mapInfos := map[uint32][]*ResponseInfo{}

		for _, node := range x.grammar.Nodes {

			info := x.SendRequest(node, true)

			mapInfos[node.Group] = append(mapInfos[node.Group], info)
			mapCodes[info.Code]++

			fmt.Printf("\r%d: %d %-7s %-100s", i+1, info.Code, info.request.Method, info.request.Path)

			if info.Code >= 500 && info.Code != 599 {

				// Set file name
				name := info.request.Path
				for _, r := range info.request.Requests {
					name += r.Type
				}

				b, err := proto.Marshal(node)
				if err != nil {
					panic(err)
				}

				t := time.Now()
				x.crashers.AddDescription([]byte(name), []byte(strconv.Itoa(info.Code)), "code")
				x.crashers.AddDescription([]byte(name), []byte(t.Format("20060102 150405")), "timestamp")
				x.crashers.AddDescription([]byte(name), b, "node")
				x.crashers.AddDescription([]byte(name), []byte(info.request.String()), "request")
				x.crashers.AddDescription([]byte(name), []byte(info.Body), "response")

			}

		}
		i++
		// Get test coverage levels
		cov := x.getCoverageLevels(mapInfos)

		// Compare with each test coverage level
		isIncrease, newCov := isIndividualIncrease(cov.Levels, x.endCov.Levels, x.strictMode)
		if isIncrease {

			// Update coverage levels
			x.endCov.Levels = newCov.Levels

			if guided {
				// Sava as new corpus
				b, err := proto.Marshal(x.grammar)
				if err != nil {
					panic(err)
				}
				x.corpus.Add(gofuzz.Artifact{Data: b})
			}
		}

		/* EVALUATION START */
		// f, err := os.OpenFile("1000_normal", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		// if err != nil {
		// 	log.Println(err)
		// }
		// defer f.Close()

		// t := ""
		// if isIncrease {
		// 	t += "1"
		// } else {
		// 	t += "0"
		// }
		// if _, err := f.WriteString(t + " | " + cov.String() + " | " + x.endCov.String() + "\n"); err != nil {
		// 	log.Println(err)
		// }
		/* EVALUATION END */

	}

	return nil

}

// New will create a new HsuanFuzz, which is also initialized.
func New(openapiPath string, dirPath string, remove bool, strictMode bool) (*HsuanFuzz, error) {

	openAPI, err := openapi3.NewSwaggerLoader().LoadSwaggerFromFile(openapiPath)
	if err != nil {
		return nil, err
	}

	servers := []string{}
	for _, server := range openAPI.Servers {
		if server.URL != "/" && !strings.HasSuffix(server.URL, ".local") && !strings.HasSuffix(server.URL, "}") {
			servers = append(servers, server.URL)
		}
	}

	if len(servers) == 0 {
		return nil, errors.New("invalid server url")
	}

	x := &HsuanFuzz{}
	x.openAPI = openAPI
	x.server = servers[0]

	// Count methods and set sorted paths
	x.sortedPaths = []string{}
	for path, pathItem := range x.openAPI.Paths {
		x.methods += len(pathItem.Operations())
		x.sortedPaths = append(x.sortedPaths, path)
	}
	sort.Strings(x.sortedPaths)

	log.Println(x.methods)

	if dirPath[:len(dirPath)-1] != "/" {
		dirPath += "/"
	}

	path := dirPath + x.openAPI.Info.Title + "/"

	if remove {
		os.RemoveAll(path + "corpus")
		fmt.Printf("Corpus has been deleted \n")
	}
	// Make directories
	os.MkdirAll(dirPath, 0770)
	os.MkdirAll(path, 0770)

	if strictMode {

		// Set paths
		dependencyPath := path + "Dependency.yml"
		tokenPath := path + "Token.yml"
		infoPath := path + "Info.yml"

		init := false
		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			init = true
			initializeTokenYAML(tokenPath)
		}
		if _, err := os.Stat(dependencyPath); os.IsNotExist(err) {
			init = true
			x.initializeDependencyYAML(dependencyPath)
		}
		if _, err := os.Stat(infoPath); os.IsNotExist(err) {
			init = true
			x.initializeInfoYAML(infoPath)
		}

		if init {
			log.Fatalln("Init success")
		}

		// Get token
		file, err := ioutil.ReadFile(tokenPath)
		if err != nil {
			panic(err)
		}

		err = yaml.Unmarshal(file, &x.Token)
		if err != nil {
			panic(err)
		}

		// Get dependencies
		file, err = ioutil.ReadFile(dependencyPath)
		if err != nil {
			panic(err)
		}

		err = yaml.Unmarshal(file, &x.dependency)
		if err != nil {
			panic(err)
		}

		if len(x.openAPI.Paths) != len(x.dependency.Paths) {
			panic("Invalid dependencies.")
		}

		if x.Token.URL == "" && x.Token.Bearer == "" {
			panic("Token.yml is not ready yet.")
		}

		for _, p := range x.dependency.Paths {
			for _, item := range p.Items {
				if item.Source.Path == "" {
					panic("Dependency.yml is not ready yet.")
				}
			}
		}

	}

	// Save responses with groups
	r := make(map[uint32]map[string]string)

	x.groupInfo = &r
	x.corpus = gofuzz.NewPersistentSet(path + "corpus")
	x.crashers = gofuzz.NewPersistentSet(path + "crashers")
	x.endCov = Coverage{Levels: make([]int, x.methods)}
	x.strictMode = strictMode

	return x, nil
}

func initializeTokenYAML(p string) {

	encoded, err := yaml.Marshal(Token{})
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(p, encoded, 0644)
	if err != nil {
		panic(err)
	}

}

func (x *HsuanFuzz) initializeDependencyYAML(p string) {

	dependency := Dependency{}
	dependency.Count = len(x.sortedPaths)
	dependency.Paths = map[string]*DependencyInfo{}
	dependency.Posts = map[string]*DependencyPost{}

	for _, path := range x.sortedPaths {
		items := []*DependencyItem{}
		items = append(items, &DependencyItem{Source: &DependencySource{}})

		dependency.Paths[path] = &DependencyInfo{}
		dependency.Paths[path].Items = items

		if x.openAPI.Paths[path].GetOperation(http.MethodPost) != nil {
			dependencyPost := DependencyPost{}
			dependencyPost.Flows = append(dependencyPost.Flows, &DependencyPostItem{Method: http.MethodGet})
			dependencyPost.Flows = append(dependencyPost.Flows, &DependencyPostItem{Method: http.MethodGet})
			dependencyPost.Flows = append(dependencyPost.Flows, &DependencyPostItem{Method: http.MethodPatch})
			dependencyPost.Flows = append(dependencyPost.Flows, &DependencyPostItem{Method: http.MethodDelete})

			dependency.Posts[path] = &dependencyPost
		}
	}

	encoded, err := yaml.Marshal(dependency)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(p, encoded, 0644)
	if err != nil {
		panic(err)
	}

}

func (x *HsuanFuzz) initializeInfoYAML(p string) {

	pathInfos := PathInfo{}
	pathInfos.Paths = map[string]*PathInfoMethod{}
	for _, path := range x.sortedPaths {
		pathInfoMethods := &PathInfoMethod{}
		pathInfoMethods.Method = map[string][]*PathInfoParameter{}
		for method, operation := range x.openAPI.Paths[path].Operations() {
			pathInfoParameters := []*PathInfoParameter{}
			for _, ref := range operation.Parameters {
				ex, err := example.GetParameterExample(example.ModeRequest, ref.Value)
				if err != nil {
					panic(err)
				}

				pathInfoParameters = append(pathInfoParameters, &PathInfoParameter{Name: ref.Value.Name, In: ref.Value.In, Value: ex})
			}

			if operation.RequestBody != nil {
				for mt, ref := range operation.RequestBody.Value.Content {
					if strings.Contains(strings.ToLower(mt), "json") {
						ex, err := example.GetBodyExample(example.ModeRequest, ref)
						if err != nil {
							panic(err)
						}

						pathInfoParameters = append(pathInfoParameters, &PathInfoParameter{Value: ex})
					}
				}
			}
			pathInfoMethods.Method[method] = pathInfoParameters
		}
		pathInfos.Paths[path] = pathInfoMethods
	}

	encoded, err := yaml.Marshal(pathInfos)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(p, encoded, 0644)
	if err != nil {
		panic(err)
	}

}

# Hsuan-Fuzz: REST API Fuzzing by Coverage Level Guided Blackbox Testing

[![Go Report Card](https://goreportcard.com/badge/github.com/iasthc/hsuan-fuzz?style=flat-square)](https://goreportcard.com/report/github.com/iasthc/hsuan-fuzz)
[![Go Reference](https://pkg.go.dev/badge/github.com/iasthc/hsuan-fuzz.svg)](https://pkg.go.dev/github.com/iasthc/hsuan-fuzz)
[![Release](https://img.shields.io/github/release/iasthc/hsuan-fuzz.svg?style=flat-square)](https://github.com/iasthc/hsuan-fuzz/releases/latest)

## Architecture
![Hsuan-Fuzz](https://user-images.githubusercontent.com/40525303/120344632-57908b00-c32c-11eb-8d36-ffdcb2c8f199.png)

## Usage
```go
package main

import (
    restAPI "github.com/iasthc/hsuan-fuzz/pkg/rest-api"
)

func main() {
    x, err := restAPI.New("OpenAPI.yaml", ".", true, true)
    if err != nil {
        panic(err)
    }
    x.Fuzz(true)
}
```

## ***WIP ...***

## Credits
- Mutation strategy
    - [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz)
- Examples of OpenAPI parameter
    - [danielgtaylor/apisprout](https://github.com/danielgtaylor/apisprout)

# Hsuan-Fuzz: REST API Fuzzing by Coverage Level Guided Blackbox Testing

[![Go Report Card](https://goreportcard.com/badge/github.com/iasthc/hsuan-fuzz?style=flat-square)](https://goreportcard.com/report/github.com/iasthc/hsuan-fuzz)
[![Go Reference](https://pkg.go.dev/badge/github.com/iasthc/hsuan-fuzz.svg)](https://pkg.go.dev/github.com/iasthc/hsuan-fuzz)
[![Release](https://img.shields.io/github/release/iasthc/hsuan-fuzz.svg?style=flat-square)](https://github.com/iasthc/hsuan-fuzz/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://github.com/iasthc/hsuan-fuzz/blob/main/LICENSE)

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

## Paper
- [[English] REST API Fuzzing by Coverage Level Guided Blackbox Testing](https://arxiv.org/abs/2112.15485)
- [[中文] 基於黑箱覆蓋等級指引之 REST API 模糊測試](https://hdl.handle.net/11296/yhymz5)

## Bugs reported
- [Spree, PR \#10626](https://github.com/spree/spree/pull/10626)
- [Spree, Issue \#10647](https://github.com/spree/spree/issues/10647)
- [Spree, Issue \#10971](https://github.com/spree/spree/issues/10971)
- [Magento2, Issue \#31551](https://github.com/magento/magento2/issues/31551)
- [Magento2, Issue \#32784](https://github.com/magento/magento2/issues/32784)

## Credits
- Mutation strategy
    - [dvyukov/go-fuzz](https://github.com/dvyukov/go-fuzz)
- Examples of OpenAPI parameter
    - [danielgtaylor/apisprout](https://github.com/danielgtaylor/apisprout)

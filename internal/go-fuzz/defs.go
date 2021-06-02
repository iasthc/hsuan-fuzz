// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gofuzz modified from https://github.com/dvyukov/go-fuzz
// Package defs provides constants required by go-fuzz-build, go-fuzz, and instrumented code.
package gofuzz

// This package has a special interaction with go-fuzz-dep:
// It is copied into a package with it by go-fuzz-build.
// Only things that can be safely duplicated without confusion,
// like constants, should be added to this package.
// And any additions should be tested carefully. :)

const (
	// CoverSize is a constant.
	CoverSize = 64 << 10
	// MaxInputSize is a constant.
	MaxInputSize = 1 << 20
	// SonarRegionSize is a constant.
	SonarRegionSize = 1 << 20
)

const (
	// SonarEQL is an enumeration.
	SonarEQL = iota
	// SonarNEQ is an enumeration.
	SonarNEQ
	// SonarLSS is an enumeration.
	SonarLSS
	// SonarGTR is an enumeration.
	SonarGTR
	// SonarLEQ is an enumeration.
	SonarLEQ
	// SonarGEQ is an enumeration.
	SonarGEQ

	// SonarOpMask is an enumeration.
	SonarOpMask = 7
	// SonarLength is an enumeration.
	SonarLength = 1 << 3
	// SonarSigned is an enumeration.
	SonarSigned = 1 << 4
	// SonarString is an enumeration.
	SonarString = 1 << 5
	// SonarConst1 is an enumeration.
	SonarConst1 = 1 << 6
	// SonarConst2 is an enumeration.
	SonarConst2 = 1 << 7

	// SonarHdrLen is an enumeration.
	SonarHdrLen = 6
	// SonarMaxLen is an enumeration.
	SonarMaxLen = 20
)

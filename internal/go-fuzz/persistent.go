// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gofuzz modified from https://github.com/dvyukov/go-fuzz
package gofuzz

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

// PersistentSet is a set of binary blobs with a persistent mirror on disk.
type PersistentSet struct {
	dir string
	M   map[Sig]Artifact
}

// Artifact is the basic element of PersistentSet.
type Artifact struct {
	Data []byte
	meta uint64 // arbitrary user payload
	user bool   // file created by user
}

// Sig for fixed-length byte.
type Sig [sha1.Size]byte

// Hash by SHA-1 checksum.
func Hash(data []byte) Sig {
	return Sig(sha1.Sum(data))
}

// NewPersistentSet for new PersistentSet.
func NewPersistentSet(dir string) *PersistentSet {
	ps := &PersistentSet{
		dir: dir,
		M:   make(map[Sig]Artifact),
	}
	os.MkdirAll(dir, 0770)
	ps.readInDir(dir)
	return ps
}

func (ps *PersistentSet) readInDir(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("error during dir walk: %v\n", err)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("error during file read: %v\n", err)
			return nil
		}
		sig := Hash(data)
		if _, ok := ps.M[sig]; ok {
			return nil
		}
		name := info.Name()
		const hexLen = 2 * sha1.Size
		if len(name) > hexLen+1 && isHexString(name[:hexLen]) && name[hexLen] == '.' {
			return nil // description file
		}
		var meta uint64
		if len(name) > hexLen+1 && isHexString(name[:hexLen]) && name[hexLen] == '-' {
			meta, _ = strconv.ParseUint(name[2*sha1.Size+1:], 10, 64)
		}
		a := Artifact{data, meta, len(name) < hexLen || !isHexString(name[:hexLen])}
		ps.M[sig] = a
		return nil
	})
}

func persistentFilename(dir string, a Artifact, sig Sig) string {
	fname := filepath.Join(dir, hex.EncodeToString(sig[:]))
	if a.meta != 0 {
		fname += fmt.Sprintf("-%v", a.meta)
	}
	return fname
}

func isHexString(s string) bool {
	for _, v := range []byte(s) {
		if v >= '0' && v <= '9' || v >= 'a' && v <= 'f' {
			continue
		}
		return false
	}
	return true
}

// Add Artifact to PersistentSet.
func (ps *PersistentSet) Add(a Artifact) bool {
	sig := Hash(a.Data)
	if _, ok := ps.M[sig]; ok {
		return false
	}
	ps.M[sig] = a
	fname := persistentFilename(ps.dir, a, sig)
	if err := ioutil.WriteFile(fname, a.Data, 0660); err != nil {
		log.Printf("failed to write file: %v", err)
	}
	return true
}

// AddDescription creates a complementary to data file on disk.
func (ps *PersistentSet) AddDescription(data []byte, desc []byte, typ string) {
	sig := Hash(data)
	fname := filepath.Join(ps.dir, fmt.Sprintf("%v.%v", hex.EncodeToString(sig[:]), typ))
	if _, err := os.Stat(fname); os.IsNotExist(err) {
		if err := ioutil.WriteFile(fname, desc, 0660); err != nil {
			log.Printf("failed to write file: %v", err)
		}
	}
}

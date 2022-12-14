// Copyright 2022-present Seal Inc. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

// Copyright (c) the purl authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package packageurl_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/seal-io/meta-api/packageurl"
)

type TestFixture struct {
	Description   string     `json:"description"`
	Purl          string     `json:"purl"`
	CanonicalPurl string     `json:"canonical_purl"`
	PackageType   string     `json:"type"`
	Namespace     string     `json:"namespace"`
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	QualifierMap  OrderedMap `json:"qualifiers"`
	Subpath       string     `json:"subpath"`
	IsInvalid     bool       `json:"is_invalid"`
}

// OrderedMap is used to store the TestFixture.QualifierMap, to ensure that the
// declaration order of qualifiers is preserved.
type OrderedMap struct {
	OrderedKeys []string
	Map         map[string]string
}

// qualifiersMapPattern is used to parse the TestFixture "qualifiers" field to
// ensure that it's a json object.
var qualifiersMapPattern = regexp.MustCompile(`^\{.*\}$`)

// UnmarshalJSON unmarshals the qualifiers field for a TestFixture. The
// qualifiers field is given as a json object such as:
//
//        "qualifiers": {"arch": "i386", "distro": "fedora-25"}
//
// This function performs in-order parsing of these values into an OrderedMap to
// preserve items in order of declaration. Note that parsing as a
// map[string]string won't preserve element order.
func (m *OrderedMap) UnmarshalJSON(bytes []byte) error {
	data := string(bytes)
	switch data {
	case "null":
		m.OrderedKeys = []string{}
		m.Map = make(map[string]string)
		return nil
	default:
		// ensure that the data is a json object "{...}"
		if !qualifiersMapPattern.MatchString(data) {
			return fmt.Errorf("qualifiers parse error: not a json object: %s", data)
		}

		// find out the order in which map keys occur
		dec := json.NewDecoder(strings.NewReader(data))
		// consume opening '{'
		_, _ = dec.Token()
		for dec.More() {
			t, _ := dec.Token()
			switch token := t.(type) {
			case json.Delim:
				if token != '}' {
					return fmt.Errorf("qualifiers parse error: expected delimiter '}', got: %v", token)
				}
				// closed json object -> we're done
			case string:
				// this token is a dictionary key
				m.OrderedKeys = append(m.OrderedKeys, token)
				// consume the value (the token following the colon after the key)
				_, _ = dec.Token()
			}
		}

		// now that we know the key order, just fill the OrderedMap.Map field
		if err := json.Unmarshal(bytes, &m.Map); err != nil {
			return err
		}
		return nil
	}
}

// Qualifiers converts the TestFixture.QualifierMap field to an object of type
// packageurl.Qualifiers.
func (t TestFixture) Qualifiers() packageurl.Qualifiers {
	q := packageurl.Qualifiers{}

	for _, key := range t.QualifierMap.OrderedKeys {
		q = append(q, packageurl.Qualifier{Key: key, Value: t.QualifierMap.Map[key]})
	}

	return q
}

// TestFromStringExamples verifies that parsing example strings produce expected
// results.
func TestFromStringExamples(t *testing.T) {
	// Read the json file
	data, err := ioutil.ReadFile("testdata/test-suite-data.json")
	if err != nil {
		t.Fatal(err)
	}
	// Load the json file contents into a structure
	testData := []TestFixture{}
	err = json.Unmarshal(data, &testData)
	if err != nil {
		t.Fatal(err)
	}

	// Use FromString on each item in the test set
	for _, tc := range testData {
		// Should parse without issue
		p, err := packageurl.FromString(tc.Purl)
		if tc.IsInvalid == false {
			if err != nil {
				t.Logf("%s failed: %s", tc.Description, err)
				t.Fail()
			}
			// verify parsing
			if p.Type != tc.PackageType {
				t.Logf("%s: incorrect package type: wanted: '%s', got '%s'", tc.Description, tc.PackageType, p.Type)
				t.Fail()
			}
			if p.Namespace != tc.Namespace {
				t.Logf("%s: incorrect namespace: wanted: '%s', got '%s'", tc.Description, tc.Namespace, p.Namespace)
				t.Fail()
			}
			if p.Name != tc.Name {
				t.Logf("%s: incorrect name: wanted: '%s', got '%s'", tc.Description, tc.Name, p.Name)
				t.Fail()
			}
			if p.Version != tc.Version {
				t.Logf("%s: incorrect version: wanted: '%s', got '%s'", tc.Description, tc.Version, p.Version)
				t.Fail()
			}
			if !reflect.DeepEqual(p.Qualifiers, tc.Qualifiers()) {
				t.Logf("%s: incorrect qualifiers: wanted: '%#v', got '%#v'", tc.Description, tc.Qualifiers(), p.Qualifiers)
				t.Fail()
			}

			if p.Subpath != tc.Subpath {
				t.Logf("%s: incorrect subpath: wanted: '%s', got '%s'", tc.Description, tc.Subpath, p.Subpath)
				t.Fail()
			}
		} else {
			// Invalid cases
			if err == nil {
				t.Logf("%s did not fail and returned %#v", tc.Description, p)
				t.Fail()
			}
		}
	}
}

// Verify correct conversion of Qualifiers to a string map and vice versa.
func TestQualifiersMapConversion(t *testing.T) {
	tests := []struct {
		kvMap      map[string]string
		qualifiers packageurl.Qualifiers
	}{
		{
			kvMap:      map[string]string{},
			qualifiers: packageurl.Qualifiers{},
		},
		{
			kvMap: map[string]string{"arch": "amd64"},
			qualifiers: packageurl.Qualifiers{
				packageurl.Qualifier{Key: "arch", Value: "amd64"},
			},
		},
		{
			kvMap: map[string]string{"arch": "amd64", "os": "linux"},
			qualifiers: packageurl.Qualifiers{
				packageurl.Qualifier{Key: "arch", Value: "amd64"},
				packageurl.Qualifier{Key: "os", Value: "linux"},
			},
		},
	}

	for _, test := range tests {
		// map -> Qualifiers
		got := packageurl.QualifiersFromMap(test.kvMap)
		if !reflect.DeepEqual(got, test.qualifiers) {
			t.Logf("map -> qualifiers conversion failed: got: %#v, wanted: %#v", got, test.qualifiers)
			t.Fail()
		}

		// Qualifiers -> map
		mp := test.qualifiers.Map()
		if !reflect.DeepEqual(mp, test.kvMap) {
			t.Logf("qualifiers -> map conversion failed: got: %#v, wanted: %#v", mp, test.kvMap)
			t.Fail()
		}

	}

}

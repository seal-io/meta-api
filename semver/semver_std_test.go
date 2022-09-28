// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package semver

import (
	"testing"
)

func TestCompare(t *testing.T) {
	type input struct {
		v, w string
	}
	type output struct {
		r int
		l bool
	}
	var testCases = []struct {
		given    input
		expected output
	}{
		{
			given: input{ // generic
				v: "1.0.0-alpha",
				w: "v1.0.0-alpha.1",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
		{
			given: input{ // generic
				v: "v1.0.0-alpha",
				w: "1.0.0-beta",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
		{
			given: input{ // generic
				v: "1.0.0-beta",
				w: "v1.0.0-rc.1",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
		{
			given: input{ // generic
				v: "v1.0.0-rc.2",
				w: "v1.0.0",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
		{
			given: input{
				v: "v1.0.0-alpha32",
				w: "v1.0.0-rc12",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
		{
			given: input{
				v: "1.35.0-r7",
				w: "1.35.0-r17",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
		{
			given: input{
				v: "85.v1d1888e8c021",
				w: "86.v7b_a_4a_55b_f3ec",
			},
			expected: output{
				r: -1,
				l: false,
			},
		},
		{
			given: input{
				v: "1155.v28a",
				w: "1156.v536a_97b_8d649",
			},
			expected: output{
				r: -1,
				l: false,
			},
		},
		{
			given: input{
				v: "1.0.0.rc2.1",
				w: "1.0.0.rc2.0",
			},
			expected: output{
				r: 1,
				l: true,
			},
		},
		{
			given: input{
				v: "1.1.0-rc.1.22152.1",
				w: "1.1.0-rc.1.22211.2",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
		{
			given: input{
				v: "1.4.25.Final",
				w: "1.4.24.FInal",
			},
			expected: output{
				r: 1,
				l: true,
			},
		},
		{
			given: input{
				v: "2.3.0.Alpha1",
				w: "2.3.0.Alpha2",
			},
			expected: output{
				r: -1,
				l: true,
			},
		},
	}

	for _, c := range testCases {
		var actual output
		actual.r, actual.l = compare(c.given.v, c.given.w)
		if actual != c.expected {
			t.Fatalf("unexpected result of compare(%s, %s), expected: %v, actual: %v", c.given.v, c.given.w, c.expected, actual)
		}
	}
}

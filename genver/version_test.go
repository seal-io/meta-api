package genver

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	var cases = []struct {
		given    string
		expected ParsedVersion
	}{
		{
			given: "v1.0.0-alpha",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"alpha"},
			},
		},
		{
			given: "v1.0.0-alpha32",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"alpha32"},
			},
		},
		{
			given: "4.2.0a",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "4",
				Minor: "2",
				Patch: "0",
				Rest:  []string{"a"},
			},
		},
		{
			given: "3.0.0alpha",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "3",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"alpha"},
			},
		},

		{
			given: "2.0b5",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "2",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"b5"},
			},
		},
		{
			given: "1.1.1k",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "1",
				Patch: "1",
				Rest:  []string{"k"},
			},
		},
		{
			given: "0.0.0-0",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "0",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"0"},
			},
		},

		{
			given: "3.0.0-CR2",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "3",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"cr2"},
			},
		},
		{
			given: "7.9.0-rc2",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "7",
				Minor: "9",
				Patch: "0",
				Rest:  []string{"rc2"},
			},
		},
		{
			given: "v1.0.0-rc.1",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"rc", "1"},
			},
		},
		{
			given: "1.0.0.rc2.0",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"rc2", "0"},
			},
		},
		{
			given: "0.2.0-prerelease.20200714185213",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "0",
				Minor: "2",
				Patch: "0",
				Rest:  []string{"prerelease", "20200714185213"},
			},
		},

		{
			given: "4.1.0.RELEASE",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "4",
				Minor: "1",
				Patch: "0",
				Rest:  []string{"release"},
			},
		},
		{
			given: "3.1-milestone-1",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "3",
				Minor: "1",
				Patch: "0",
				Rest:  []string{"milestone", "1"},
			},
		},
		{
			given: "2.3.0.M1",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "2",
				Minor: "3",
				Patch: "0",
				Rest:  []string{"m1"},
			},
		},
		{
			given: "3.0.0-stable",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "3",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"stable"},
			},
		},
		{
			given: "4.3.5.Final",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "4",
				Minor: "3",
				Patch: "5",
				Rest:  []string{"final"},
			},
		},
		{
			given: "3.3.3.FINAL",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "3",
				Minor: "3",
				Patch: "3",
				Rest:  []string{"final"},
			},
		},
		{
			given: "4.2.0ga",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "4",
				Minor: "2",
				Patch: "0",
				Rest:  []string{"ga"},
			},
		},

		{
			given: "86.v7b_a_4a_55b_f3ec",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "86",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"v7b", "a", "4a", "55b", "f3ec"},
				Err:   "invalid minor",
			},
		},
		{
			given: "canvaskit/0.25.1",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "0",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"canvaskit", "0", "25", "1"},
				Err:   "invalid major",
			},
		},
		{
			given: "apache-arrow-0.17.0",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "0",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"apache", "arrow", "0", "17", "0"},
				Err:   "invalid major",
			},
		},
		{
			given: "1:3.3.0~rc10-4",
			expected: ParsedVersion{
				Epoch: "1",
				Major: "3",
				Minor: "3",
				Patch: "0",
				Rest:  []string{"rc10", "4"},
			},
		},
		{
			given: "1~~rc10-4",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"rc10", "4"},
			},
		},
		{
			given: "1.09.006~7",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "9",
				Patch: "6",
				Rest:  []string{"7"},
			},
		},
		{
			given: "1.09a.006~7",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "1",
				Minor: "9",
				Patch: "0",
				Rest:  []string{"a", "006", "7"},
			},
		},
		{
			given: "x:3.3.0~rc10-4",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "0",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"x", "3", "3", "0", "rc10", "4"},
				Err:   "invalid version",
			},
		},
		{
			given: "y:",
			expected: ParsedVersion{
				Epoch: "0",
				Major: "0",
				Minor: "0",
				Patch: "0",
				Rest:  []string{"y"},
				Err:   "invalid version",
			},
		},
	}
	for _, c := range cases {
		var actual = Parse(c.given)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("parse(%q) == %v, but got %v", c.given, c.expected, actual)
		}
	}
}

func TestCompare(t *testing.T) {
	type input struct {
		v string
		w string
	}
	var cases = []struct {
		given    input
		expected int
	}{
		{
			given:    input{"1", "v2"},
			expected: -1,
		},
		{
			given:    input{"1.2", "1.1.2"},
			expected: +1,
		},
		{
			given:    input{"v1.1.1", "v1.1.2"},
			expected: -1,
		},
		{
			given:    input{"1.1.2", "1.1.13"},
			expected: -1,
		},
		{
			given:    input{"v1.0.0-alpha", "v1.0.0-beta"},
			expected: -1,
		},
		{
			given:    input{"v1.0.0-rc", "v1.0.0-beta"},
			expected: +1,
		},
		{
			given:    input{"v1.0.0-rc1", "v1.0.0-rc2"},
			expected: -1,
		},
		{
			given:    input{"v1.0.0-alpha32", "v1.0.0-rc2"},
			expected: -1,
		},
		{
			given:    input{"4.2.0", "4.2.0b"},
			expected: +1,
		},
		{
			given:    input{"2.0b5", "2.0-rc4"},
			expected: -1,
		},
		{
			given:    input{"2.0b5", "2.0b4"},
			expected: +1,
		},
		{
			given:    input{"2.05.6.r1", "2.05.6-r2"},
			expected: -1,
		},
		{
			given:    input{"1.1.1k", "1.1.1f"},
			expected: +1,
		},
		{
			given:    input{"3.0.0-RC2", "3.0.0-CR2"},
			expected: 0,
		},
		{
			given:    input{"1.0.0.rc2.0", "1.0.0.rc3"},
			expected: -1,
		},
		{
			given:    input{"1.0.0.rc2.1", "1.0.0.rc1.1"},
			expected: +1,
		},
		{
			given:    input{"3.1-milestone-1", "v3.1.m1"},
			expected: 0,
		},
		{
			given:    input{"3.2.2.Final", "3.2.2.M1"},
			expected: +1,
		},
		{
			given:    input{"1:3.3.0~rc10-4", "1:3.3.0~rc10-5"},
			expected: -1,
		},
		{
			given:    input{"1:3.3.0~rc11-4", "1:3.3.0~rc9"},
			expected: +1,
		},
		{
			given:    input{"1:3.3.0+rc11-4", "2:3.2.1+rc11"},
			expected: -1,
		},
		{
			given:    input{"v0.0.0-20220526004731-065cf7ba2467", "v0.0.0-20210526004731-065cf7ba2467"},
			expected: +1,
		},
		{
			given:    input{"1.0.0-alpha", "v1.0.0-alpha.1"},
			expected: -1,
		},
		{
			given:    input{"v1.0.0-alpha", "1.0-beta"},
			expected: -1,
		},
		{
			given:    input{"1.0.0-beta", "v1.0.0-rc.1"},
			expected: -1,
		},
		{
			given:    input{"v1.0.0-rc.2", "v1.0.0"},
			expected: -1,
		},
		{
			given:    input{"85.v1d1888e8c021", "86.v7b_a_4a_55b_f3ec"},
			expected: -1,
		},
		{
			given:    input{"1155.v536a_97b_8d649", "1155.v28a"},
			expected: +1,
		},
		{
			given:    input{"2.3.0.Alpha1", "2.3.0.Alpha2"},
			expected: -1,
		},
		{
			given:    input{"1.1.0-rc.1.22152.1", "1.1.0-rc.1.22211.2"},
			expected: -1,
		},
		{
			given:    input{"1.1.0", "1.1.0-x+y"}, // as larger as more detail
			expected: 1,
		},
	}
	for _, c := range cases {
		var actual = Compare(c.given.v, c.given.w)
		if actual != c.expected {
			t.Errorf("compare(%q, %q) == %v, but got %v", c.given.v, c.given.w, c.expected, actual)
		}
	}
}

func TestIsRelease(t *testing.T) {
	var cases = []struct {
		given    string
		expected bool
	}{
		{
			given:    "v1.0.0-alpha",
			expected: false,
		},
		{
			given:    "v1.0.0-alpha32",
			expected: false,
		},
		{
			given:    "4.2.0a",
			expected: false,
		},
		{
			given:    "3.0.0alpha",
			expected: false,
		},

		{
			given:    "2.0b5",
			expected: false,
		},
		{
			given:    "1.1.1k",
			expected: false,
		},
		{
			given:    "0.0.0-0",
			expected: false,
		},

		{
			given:    "3.0.0-CR2",
			expected: false,
		},
		{
			given:    "7.9.0-rc2",
			expected: false,
		},
		{
			given:    "v1.0.0-rc.1",
			expected: false,
		},
		{
			given:    "1.0.0.rc2.0",
			expected: false,
		},
		{
			given:    "0.2.0-prerelease.20200714185213",
			expected: false,
		},
		{
			given:    "4.1.0.RELEASE",
			expected: true,
		},
		{
			given:    "3.1-milestone-1",
			expected: false,
		},
		{
			given:    "2.3.0.M1",
			expected: false,
		},
		{
			given:    "3.0.0-stable",
			expected: true,
		},
		{
			given:    "4.3.5.Final",
			expected: true,
		},
		{
			given:    "3.3.3.FINAL",
			expected: true,
		},
		{
			given:    "4.2.0ga",
			expected: true,
		},

		{
			given:    "86.v7b_a_4a_55b_f3ec",
			expected: false,
		},
		{
			given:    "4.12-beta-1",
			expected: false,
		},
		{
			given:    "apache-arrow-0.17.0",
			expected: false,
		},
	}
	for _, c := range cases {
		var actual = IsRelease(c.given)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("parse(%q) == %v, but got %v", c.given, c.expected, actual)
		}
	}
}

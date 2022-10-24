// Package genver inspires by golang.org/x/mod/semver,
// and processes none semantic standard version.
package genver

import (
	"strings"
)

// IsValid returns true if the version is parse-able.
func IsValid(v string) bool {
	pv := parse(v)
	return pv.Err == ""
}

// IsRelease returns true if the version is release version.
func IsRelease(v string) bool {
	pv := parse(v)
	if pv.Err != "" {
		return false
	}

	if len(pv.Rest) == 0 {
		return true
	}

	return isRelease(pv.Rest[0])
}

// Epoch returns the epoch version without v prefix,
// if v is an invalid version string, Epoch returns the empty string.
// e.g. Epoch("v2.1.0") == "0", Epoch("1:2.1.0") == "1", Epoch("0:2.1.0") == "0".
func Epoch(v string) string {
	pv := parse(v)
	if pv.Err != "" {
		return ""
	}
	return pv.Epoch
}

// Major returns the major version without v prefix,
// if v is an invalid version string, Major returns the empty string.
// e.g. Major("v2.1.0") == "2", Major("1:2.1.0") == "1:2", Major("0:2.1.0") == "2".
func Major(v string) string {
	pv := parse(v)
	if pv.Err != "" {
		return ""
	}
	if pv.Epoch != "0" {
		return pv.Epoch + ":" + pv.Major
	}
	return pv.Major
}

// MajorMinor returns the major.minor version without v prefix,
// if v is an invalid version string, MajorMinor returns the empty string.
// e.g. MajorMinor("v2.1.0") == "2.1", MajorMinor("1:2.1.0") == "1:2.1", MajorMinor("0:2.1.0") == "2.1".
func MajorMinor(v string) string {
	pv := parse(v)
	if pv.Err != "" {
		return ""
	}
	if pv.Epoch != "0" {
		return pv.Epoch + ":" + pv.Major
	}
	return pv.Major + "." + pv.Minor
}

// Compare returns an integer comparing two versions according to version precedence.
// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
func Compare(v, w string) int {
	pv := parse(v)
	pw := parse(w)
	return compare(pv, pw)
}

// Parse parses the given version string into a comparable struct.
func Parse(v string) ParsedVersion {
	return parse(v)
}

// ParsedVersion holds the version information after parsed.
type ParsedVersion struct {
	Epoch string
	Major string
	Minor string
	Patch string
	Rest  []string
	Err   string
}

func (pv ParsedVersion) Compare(w string) int {
	pw := parse(w)
	return compare(pv, pw)
}

func (pv ParsedVersion) IsZero() bool {
	return pv.Epoch == "" &&
		pv.Major == "" &&
		pv.Minor == "" &&
		pv.Patch == "" &&
		len(pv.Rest) == 0 &&
		pv.Err == ""
}

func (pv ParsedVersion) Lt(w string) bool {
	return pv.Compare(w) < 0
}

func (pv ParsedVersion) Gt(w string) bool {
	return pv.Compare(w) > 0
}

func (pv ParsedVersion) Le(w string) bool {
	return pv.Compare(w) <= 0
}

func (pv ParsedVersion) Ge(w string) bool {
	return pv.Compare(w) >= 0
}

func (pv ParsedVersion) Eq(w string) bool {
	return pv.Compare(w) == 0
}

// nolint:cyclop
func parse(v string) (p ParsedVersion) {
	if v == "" {
		return
	}
	if v[0] == 'v' {
		v = v[1:]
	}
	if ei := strings.Index(v, ":"); ei > 0 {
		p.Epoch, _ = parseInt(v[:ei])
		if p.Epoch == "" {
			// rest
			p.Epoch = "0"
			p.Major = "0"
			p.Minor = "0"
			p.Patch = "0"
			p.Rest = parseRest(v)
			p.Err = "invalid version"
			return
		} else {
			v = v[ei+1:]
		}
	} else {
		p.Epoch = "0"
	}

	p.Major, v = parseInt(v)
	if p.Major == "" {
		// rest
		p.Major = "0"
		p.Minor = "0"
		p.Patch = "0"
		p.Rest = parseRest(v)
		p.Err = "invalid major"
		return
	}
	if v == "" {
		// v1
		p.Minor = "0"
		p.Patch = "0"
		return
	}
	if v[0] != '.' {
		// v1-rest, v2+rest
		p.Minor = "0"
		p.Patch = "0"
		p.Rest = parseRest(v)
		return
	}
	p.Minor, v = parseInt(v[1:])
	if p.Minor == "" {
		// v1.rest
		p.Minor = "0"
		p.Patch = "0"
		p.Rest = parseRest(v)
		p.Err = "invalid minor"
		return
	}
	if v == "" {
		// v1.1
		p.Patch = "0"
		return
	}
	if v[0] != '.' {
		// v1.1-rest, v2.1+rest
		p.Patch = "0"
		p.Rest = parseRest(v)
		return
	}
	p.Patch, v = parseInt(v[1:])
	if p.Patch == "" {
		// v1.1.rest
		p.Patch = "0"
		p.Rest = parseRest(v)
		p.Err = "invalid patch"
		return
	}
	// v1.1.1-rest, v1.1.1+rest
	p.Rest = parseRest(v)
	return
}

func parseInt(v string) (string, string) {
	if v == "" {
		return "", ""
	}
	if v[0] < '0' || '9' < v[0] {
		return "", v
	}
	i := 1
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	if v[0] == '0' && i != 1 {
		return parseOrdinalInt(v[:i]), v[i:]
	}
	return v[:i], v[i:]
}

func parseOrdinalInt(v string) string {
	i := 0
	for i < len(v) && '0' == v[i] {
		i++
	}
	return v[i:]
}

func parseRest(v string) (r []string) {
	var s, e int
	for ; e < len(v); e++ {
		switch v[e] {
		case '-', '_', '+', '.', '~', '/', '\\', ':':
			if s+1 <= e {
				r = append(r, strings.ToLower(v[s:e]))
			}
			s = e + 1
		}
	}
	if s+1 <= e {
		r = append(r, strings.ToLower(v[s:e]))
	}
	return
}

func compare(pv, pw ParsedVersion) int {
	if c := compareInt(pv.Epoch, pw.Epoch); c != 0 {
		return c
	}
	if c := compareInt(pv.Major, pw.Major); c != 0 {
		return c
	}
	if c := compareInt(pv.Minor, pw.Minor); c != 0 {
		return c
	}
	if c := compareInt(pv.Patch, pw.Patch); c != 0 {
		return c
	}
	return compareRest(pv.Rest, pw.Rest)
}

func compareInt(x, y string) int {
	if x == y {
		return 0
	}
	if len(x) < len(y) {
		return -1
	}
	if len(x) > len(y) {
		return +1
	}
	if x < y {
		return -1
	}
	return +1
}

func compareRest(x, y []string) int {
	if len(x) == 0 && len(y) == 0 {
		return 0
	}
	if len(x) == 0 {
		// evaluate y
		if isRelease(y[0]) {
			return 0
		}
		return +1
	}
	if len(y) == 0 {
		// evaluate x
		if isRelease(x[0]) {
			return 0
		}
		return -1
	}
	// evaluate both
	if x0, y0, c := compareRelease(x[0], y[0]); c != 0 {
		return c
	} else {
		if x0 != "" {
			x[0] = x0
		} else {
			x = x[1:]
		}
		if y0 != "" {
			y[0] = y0
		} else {
			y = y[1:]
		}
	}
	l := len(x)
	if len(y) < l {
		l = len(y)
	}
	for i := 0; i < l; i++ {
		if isNum(x[i]) && isNum(y[i]) {
			if c := compareInt(x[i], y[i]); c != 0 {
				return c
			}
		}
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return +1
		}
	}
	if l < len(y) {
		return -1
	}
	if l < len(x) {
		return +1
	}
	return 0
}

// nolint:cyclop
func compareRelease(v, w string) (v0 string, w0 string, s int) {
	if v == w {
		return
	}

	vs, ws := scoreRelease(v), scoreRelease(w)
	if vs != 0 && ws != 0 {
		s = normalDiff(vs - ws)
		return
	}

	if vs >= 60 {
		// v is release, but w is unknown
		w, w0 = parseRelease(w)
		ws = scoreRelease(w)
		if ws >= 60 {
			// v and w are release
			s = normalDiff(vs - ws)
			return
		}
		s = +1
		return
	} else if vs > 0 {
		// v is prerelease, but w is unknown
		w, w0 = parseRelease(w)
		ws = scoreRelease(w)
		if ws != 0 {
			// w is release or prerelease
			s = normalDiff(vs - ws)
			return
		}
		s = -1
		return
	}
	if ws >= 60 {
		// w is release, but v is unknown
		v, v0 = parseRelease(v)
		vs = scoreRelease(v)
		if vs >= 60 {
			// w and v are release
			s = normalDiff(vs - ws)
			return
		}
		s = -1
		return
	} else if ws > 0 {
		// w is prerelease, but v is unknown
		v, v0 = parseRelease(v)
		vs = scoreRelease(v)
		if vs != 0 {
			// v is release or prerelease
			s = normalDiff(vs - ws)
			return
		}
		s = +1
		return
	}

	// both unknown
	{
		var uv, uv0 = parseRelease(v)
		var uw, uw0 = parseRelease(w)
		vs, ws = scoreRelease(uv), scoreRelease(uw)
		if vs != 0 && ws != 0 {
			s = normalDiff(vs - ws)
			v0 = uv0
			w0 = uw0
			return
		}
	}

	if v < w {
		s = -1
		return
	}
	if v > w {
		s = +1
		return
	}
	return
}

func scoreRelease(v string) int {
	switch v {
	case "servicepack", "sp":
		return 70
	case "release", "r", "ga", "final", "stable", "s":
		return 60
	case "prerelease", "rc", "cr":
		return 50
	case "milestone", "mc", "m":
		return 40
	case "snapshot":
		return 30
	case "beta", "b":
		return 20
	case "alpha", "a":
		return 10
	}
	return 0
}

func parseRelease(v string) (string, string) {
	i := len(v) - 1
	for i >= 0 && ('0' <= v[i] && v[i] <= '9') {
		i--
	}
	return v[:i+1], v[i+1:]
}

func isRelease(v string) bool {
	return scoreRelease(v) >= 60
}

func normalDiff(s int) int {
	if s < 0 {
		return -1
	}
	if s > 0 {
		return +1
	}
	return 0
}

func isNum(v string) bool {
	i := 0
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	return i == len(v)
}

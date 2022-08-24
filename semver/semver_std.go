// parsing got from on golang.org/x/mod/semver is covered by the BSD License with Copyright (c) 2018, Go Authors.

package semver

type parsed struct {
	major      string
	minor      string
	patch      string
	short      string
	prerelease string
	build      string
	rest       string
	err        string
}

// IsValid reports whether v is a valid semantic version string.
func IsValid(v string) bool {
	_, ok := parse(v)
	return ok
}

// Canonical returns the canonical formatting of the semantic version v.
// It fills in any missing .MINOR or .PATCH and discards build metadata.
// Two semantic versions compare equal only if their canonical formattings
// are identical strings.
// The canonical invalid semantic version is the empty string.
func Canonical(v string) string {
	p, ok := parse(v)
	if !ok {
		return ""
	}
	if p.build != "" {
		return v[:len(v)-len(p.build)]
	}
	if p.short != "" {
		return v + p.short
	}
	return v
}

// Major returns the major version prefix of the semantic version v.
// For example, Major("v2.1.0") == "v2".
// If v is an invalid semantic version string, Major returns the empty string.
func Major(v string) string {
	pv, ok := parse(v)
	if !ok {
		return ""
	}
	return v[:1+len(pv.major)]
}

// MajorMinor returns the major.minor version prefix of the semantic version v.
// For example, MajorMinor("v2.1.0") == "v2.1".
// If v is an invalid semantic version string, MajorMinor returns the empty string.
func MajorMinor(v string) string {
	pv, ok := parse(v)
	if !ok {
		return ""
	}
	i := 1 + len(pv.major)
	if j := i + 1 + len(pv.minor); j <= len(v) && v[i] == '.' && v[i+1:j] == pv.minor {
		return v[:j]
	}
	return v[:i] + "." + pv.minor
}

// Prerelease returns the prerelease suffix of the semantic version v.
// For example, Prerelease("v2.1.0-pre+meta") == "-pre".
// If v is an invalid semantic version string, Prerelease returns the empty string.
func Prerelease(v string) string {
	pv, ok := parse(v)
	if !ok {
		return ""
	}
	return pv.prerelease
}

// Build returns the build suffix of the semantic version v.
// For example, Build("v2.1.0+meta") == "+meta".
// If v is an invalid semantic version string, Build returns the empty string.
func Build(v string) string {
	pv, ok := parse(v)
	if !ok {
		return ""
	}
	return pv.build
}

// Compare returns an integer comparing two versions according to
// semantic version precedence.
// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
//
// An invalid semantic version string is considered less than a valid one.
// All invalid semantic version strings compare equal to each other.
func Compare(v, w string) int {
	var r, _ = compare(v, w)
	return r
}

// compare returns an integer comparing two versions according to
// semantic version precedence,
// the result will be 0 if v == w, -1 if v < w, or +1 if v > w.
//
// compare returns false parsed bool signal, if failed to parse the version.
//
// Unlike the native golang.org/x/mod/semver Compare function, it can handle the following cases:
// - without a 'v' prefix,
// - take over with rest if cannot parsing prerelease or build.
func compare(v, w string) (int, bool) {
	pv, ok1 := parse(v)
	pw, ok2 := parse(w)
	if !ok1 && !ok2 {
		return 0, false
	}
	if !ok1 {
		return -1, false
	}
	if !ok2 {
		return +1, false
	}
	if c := compareInt(pv.major, pw.major); c != 0 {
		return c, true
	}
	if c := compareInt(pv.minor, pw.minor); c != 0 {
		return c, true
	}
	if c := compareInt(pv.patch, pw.patch); c != 0 {
		return c, true
	}
	if c := comparePrerelease(pv.prerelease, pw.prerelease); c != 0 {
		return c, true
	}
	var c = compareRest(pv.rest, pw.rest)
	return c, true
}

func parse(v string) (p parsed, ok bool) {
	if v == "" {
		p.err = "missing v prefix"
		return
	}
	if v[0] == 'v' {
		v = v[1:]
	}
	p.major, v, ok = parseInt(v)
	if !ok {
		p.err = "bad major version"
		return
	}
	if v == "" {
		p.minor = "0"
		p.patch = "0"
		p.short = ".0.0"
		return
	}
	if v[0] != '.' {
		p.err = "bad minor prefix"
		// ok = false
		p.rest = v // take over with rest
		return
	}
	p.minor, v, ok = parseInt(v[1:])
	if !ok {
		p.err = "bad minor version"
		return
	}
	if v == "" {
		p.patch = "0"
		p.short = ".0"
		return
	}
	if v[0] != '.' {
		p.err = "bad patch prefix"
		// ok = false
		p.rest = v // take over with rest
		return
	}
	p.patch, v, ok = parseInt(v[1:])
	if !ok {
		p.err = "bad patch version"
		return
	}
	if len(v) > 0 && v[0] == '-' {
		p.prerelease, v, ok = parsePrerelease(v)
		if !ok {
			p.err = "bad prerelease"
			return
		}
	}
	if len(v) > 0 && v[0] == '+' {
		p.build, v, ok = parseBuild(v)
		if !ok {
			p.err = "bad build"
			return
		}
	}
	if v != "" {
		p.err = "junk on end"
		// ok = false
		p.rest = v // take over with rest
		return
	}
	ok = true
	return
}

func parseInt(v string) (t, rest string, ok bool) {
	if v == "" {
		return
	}
	if v[0] < '0' || '9' < v[0] {
		return
	}
	i := 1
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	if v[0] == '0' && i != 1 {
		return
	}
	return v[:i], v[i:], true
}

func parsePrerelease(v string) (t, rest string, ok bool) {
	// "A pre-release version MAY be denoted by appending a hyphen and
	// a series of dot separated identifiers immediately following the patch version.
	// Identifiers MUST comprise only ASCII alphanumerics and hyphen [0-9A-Za-z-].
	// Identifiers MUST NOT be empty. Numeric identifiers MUST NOT include leading zeroes."
	if v == "" || v[0] != '-' {
		return
	}
	i := 1
	start := 1
	for i < len(v) && v[i] != '+' {
		if !isIdentChar(v[i]) && v[i] != '.' {
			return
		}
		if v[i] == '.' {
			if start == i || isBadNum(v[start:i]) {
				return
			}
			start = i + 1
		}
		i++
	}
	if start == i || isBadNum(v[start:i]) {
		return
	}
	return v[:i], v[i:], true
}

func parseBuild(v string) (t, rest string, ok bool) {
	if v == "" || v[0] != '+' {
		return
	}
	i := 1
	start := 1
	for i < len(v) {
		if !isIdentChar(v[i]) && v[i] != '.' {
			return
		}
		if v[i] == '.' {
			if start == i {
				return
			}
			start = i + 1
		}
		i++
	}
	if start == i {
		return
	}
	return v[:i], v[i:], true
}

func isIdentChar(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-'
}

func isBadNum(v string) bool {
	i := 0
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	return i == len(v) && i > 1 && v[0] == '0'
}

func isNum(v string) bool {
	i := 0
	for i < len(v) && '0' <= v[i] && v[i] <= '9' {
		i++
	}
	return i == len(v)
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
	} else {
		return +1
	}
}

// nolint:nestif
func comparePrerelease(x, y string) int {
	// "When major, minor, and patch are equal, a pre-release version has
	// lower precedence than a normal version.
	// Example: 1.0.0-alpha < 1.0.0.
	// Precedence for two pre-release versions with the same major, minor,
	// and patch version MUST be determined by comparing each dot separated
	// identifier from left to right until a difference is found as follows:
	// identifiers consisting of only digits are compared numerically and
	// identifiers with letters or hyphens are compared lexically in ASCII
	// sort order. Numeric identifiers always have lower precedence than
	// non-numeric identifiers. A larger set of pre-release fields has a
	// higher precedence than a smaller set, if all of the preceding
	// identifiers are equal.
	// Example: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta <
	// 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0."
	if x == y {
		return 0
	}
	if x == "" {
		return +1
	}
	if y == "" {
		return -1
	}
	for x != "" && y != "" {
		x = x[1:] // skip - or .
		y = y[1:] // skip - or .
		var dx, dy string
		dx, x = nextIdent(x)
		dy, y = nextIdent(y)
		if dx != dy {
			ix := isNum(dx)
			iy := isNum(dy)
			if ix != iy {
				if ix {
					return -1
				} else {
					return +1
				}
			}
			if ix {
				if len(dx) < len(dy) {
					return -1
				}
				if len(dx) > len(dy) {
					return +1
				}
			}
			if dx < dy {
				return -1
			} else {
				return +1
			}
		}
	}
	if x == "" {
		return -1
	} else {
		return +1
	}
}

func compareRest(x, y string) int {
	return compareInt(x, y)
}

func nextIdent(x string) (dx, rest string) {
	i := 0
	for i < len(x) && x[i] != '.' {
		i++
	}
	return x[:i], x[i:]
}
package packageurl

import (
	"sort"
	"strings"

	"github.com/seal-io/meta-api/semver"
)

func (p PackageURL) Equal(q PackageURL) bool {
	if p.Type != q.Type {
		return false
	}
	if p.Namespace != q.Namespace {
		return false
	}
	if p.Name != q.Name {
		return false
	}

	if p.Version != q.Version {
		return false
	}

	if len(p.Qualifiers) != len(q.Qualifiers) {
		return false
	}
	sort.Slice(p.Qualifiers, func(i, j int) bool {
		return p.Qualifiers[i].Key < p.Qualifiers[j].Key
	})
	sort.Slice(q.Qualifiers, func(i, j int) bool {
		return q.Qualifiers[i].Key < q.Qualifiers[j].Key
	})
	for i := range p.Qualifiers {
		if p.Qualifiers[i] != q.Qualifiers[i] {
			return false
		}
	}

	if p.Subpath == "" {
		p.Subpath = "/"
	}
	if q.Subpath == "" {
		q.Subpath = "/"
	}
	return p.Subpath == q.Subpath
}

func (p PackageURL) CompatibleWith(q PackageURL) bool {
	if p.Type != q.Type {
		return false
	}
	if p.Namespace != q.Namespace {
		return false
	}
	if p.Name != q.Name {
		return false
	}

	if semver.MajorMinor(p.Version) != semver.MajorMinor(q.Version) {
		return false
	}

	if len(p.Qualifiers) != 0 && len(q.Qualifiers) != 0 {
		var pm, qm = p.Qualifiers.Map(), q.Qualifiers.Map()
		if !isDistroEqual(p.Type, pm["distro"], qm["distro"]) {
			return false
		}
		if !isOSEqual(p.Type, pm["os"], qm["os"]) {
			return false
		}
		if !isArchEqual(p.Type, pm["arch"], qm["arch"]) {
			return false
		}
	}

	if p.Subpath == "" {
		p.Subpath = "/"
	}
	if q.Subpath == "" {
		q.Subpath = "/"
	}
	return strings.HasPrefix(q.Subpath, p.Subpath)
}

func isDistroEqual(typ string, p, q string) bool {
	p = strings.ToLower(p)
	q = strings.ToLower(q)
	if p == "" && q == "" {
		return true
	}
	if p == "" || q == "" {
		return false
	}
	return p == q
}

func isOSEqual(typ string, p, q string) bool {
	p = strings.ToLower(p)
	q = strings.ToLower(q)
	if p == "" && q == "" {
		return true
	}
	if p == "" || q == "" {
		return false
	}
	if p == q {
		return true
	}
	// NB(thxCode): try to compare some words that are synonymous but atypical.
	return normalizeOS(typ, p) == normalizeOS(typ, q)
}

func normalizeOS(typ string, v string) string {
	if strings.HasPrefix(v, "cygwin_nt") {
		return "windows"
	}
	if strings.HasPrefix(v, "mingw") {
		return "windows"
	}
	if strings.HasPrefix(v, "msys_nt") {
		return "windows"
	}
	return v
}

func isArchEqual(typ string, p, q string) bool {
	p = strings.ToLower(p)
	q = strings.ToLower(q)
	if p == "" && q == "" {
		return true
	}
	if p == "all" || q == "all" ||
		p == "*" || q == "*" {
		return true
	}
	if p == "" || q == "" {
		return false
	}
	if p == q {
		return true
	}
	// NB(thxCode): try to compare some words that are synonymous but atypical.
	return normalizeArch(typ, p) == normalizeArch(typ, q)
}

func normalizeArch(typ string, v string) string {
	switch v {
	case "aarch64":
		return "arm64"
	case "x86":
		return "386"
	case "i686":
		return "386"
	case "i386":
		return "386"
	case "x86_64":
		return "amd64"
	}
	if strings.HasPrefix(v, "armv5") {
		return "armv5"
	}
	if strings.HasPrefix(v, "armv6") {
		return "armv6"
	}
	if strings.HasPrefix(v, "armv7") {
		return "arm"
	}
	if strings.HasPrefix(v, "armv8") {
		return "arm64"
	}
	return v
}

package packageurl

import (
	"sort"
	"strings"

	"github.com/seal-io/meta-api/semver"
)

// Equal returns true if everything of the given package url are the same.
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

type _CompatibleWithOptions struct {
	IgnoreVersion bool
	IgnoreDistro  bool
	IgnoreOS      bool
	IgnoreArch    bool
	IgnoreSubpath bool
}

type CompatibleOption func(*_CompatibleWithOptions)

func WithoutVersion() CompatibleOption {
	return func(o *_CompatibleWithOptions) {
		o.IgnoreVersion = true
	}
}

func WithoutDistro() CompatibleOption {
	return func(o *_CompatibleWithOptions) {
		o.IgnoreDistro = true
	}
}

func WithoutOS() CompatibleOption {
	return func(o *_CompatibleWithOptions) {
		o.IgnoreOS = true
	}
}

func WithoutArch() CompatibleOption {
	return func(o *_CompatibleWithOptions) {
		o.IgnoreArch = true
	}
}

func WithoutSubpath() CompatibleOption {
	return func(o *_CompatibleWithOptions) {
		o.IgnoreSubpath = true
	}
}

// CompatibleWith returns true if the following criteria of the given package url are the same.
//  - type/namespace/name
//  - [optional] major.minor of the version
//  - [optional] distro/os/arch of the qualifiers
//  - [optional] subpath
// the optional conditions can be disabled by CompatibleOption.
func (p PackageURL) CompatibleWith(q PackageURL, opts ...CompatibleOption) bool {
	var o _CompatibleWithOptions
	for i := range opts {
		if opts[i] == nil {
			continue
		}
		opts[i](&o)
	}

	if p.Type != q.Type {
		return false
	}
	if p.Namespace != q.Namespace {
		return false
	}
	if p.Name != q.Name {
		return false
	}

	if !o.IgnoreVersion && semver.MajorMinor(p.Version) != semver.MajorMinor(q.Version) {
		return false
	}

	if len(p.Qualifiers) != 0 && len(q.Qualifiers) != 0 {
		var pm, qm = p.Qualifiers.Map(), q.Qualifiers.Map()
		if !o.IgnoreDistro && !isDistroEqual(p.Type, pm["distro"], qm["distro"]) {
			return false
		}
		if !o.IgnoreOS && !isOSEqual(p.Type, pm["os"], qm["os"]) {
			return false
		}
		if !o.IgnoreArch && !isArchEqual(p.Type, pm["arch"], qm["arch"]) {
			return false
		}
	}

	if o.IgnoreSubpath {
		return true
	}
	if p.Subpath == "" {
		p.Subpath = "/"
	}
	if q.Subpath == "" {
		q.Subpath = "/"
	}
	return strings.HasPrefix(q.Subpath, p.Subpath)
}

// IsLinuxDistro returns true if the package is a Linux distro.
func (p PackageURL) IsLinuxDistro() bool {
	return IsLinuxPackage(&p) && IsDistroPackage(&p)
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
	if p == q {
		return true
	}
	return strings.HasPrefix(p, q) || strings.HasPrefix(q, p)
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

// IsLinuxPackage returns true if the given package type is managed by some kinds of Linux Package Manager.
func IsLinuxPackage(p *PackageURL) bool {
	switch p.Type {
	case TypeRPM, TypeDebian, TypeALPM, TypeAlpine:
		return true
	}
	return false
}

// IsDistroPackage returns true if the given package qualifiers has a distro limitation.
func IsDistroPackage(p *PackageURL) bool {
	for i := range p.Qualifiers {
		if p.Qualifiers[i].Key == "distro" {
			return p.Qualifiers[i].Value != ""
		}
	}
	return false
}

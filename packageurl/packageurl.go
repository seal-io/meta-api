// Package packageurl implements the https://github.com/package-url/purl-spec.
package packageurl

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

var (
	// QualifierKeyPattern describes a valid qualifier key:
	//
	// - The key must be composed only of ASCII letters and numbers, '.',
	//   '-' and '_' (period, dash and underscore).
	// - A key cannot start with a number.
	QualifierKeyPattern = regexp.MustCompile(`^[A-Za-z\.\-_][0-9A-Za-z\.\-_]*$`)
)

// These are the known purl types as defined in the spec. Some of these require
// special treatment during parsing.
// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#known-purl-types
const (
	// TypeALPM is a pkg:alpm purl for Arch Linux and other users of the libalpm/pacman package manager, no default package repository.
	TypeALPM = "alpm"
	// TypeBitbucket is a pkg:bitbucket purl for Bitbucket-based packages, default repository is https://bitbucket.org.
	TypeBitbucket = "bitbucket"
	// TypeCocoapods is a pkg:cocoapods purl for Cocoapods, default repository is https://cdn.cocoapods.org/.
	TypeCocoapods = "cocoapods"
	// TypeCargo is a pkg:cargo purl for Rust packages, default repository is https://crates.io/.
	TypeCargo = "cargo"
	// TypeComposer is a pkg:composer purl for Composer PHP packages, default repository is https://packagist.org.
	TypeComposer = "composer"
	// TypeConan is a pkg:conan purl for Conan C/C++ packages, default repository is https://center.conan.io.
	TypeConan = "conan"
	// TypeConda is a pkg:conda purl for Conda packages, default repository is https://repo.anaconda.com.
	TypeConda = "conda"
	// TypeCran is a pkg:cran purl for CRAN R packages, default repository is https://cran.r-project.org.
	TypeCran = "cran"
	// TypeDebian is a pkg:deb purl for Debian, Debian derivatives, and Ubuntu packages, no default package repository.
	TypeDebian = "deb"
	// TypeDocker is a pkg:docker purl for Docker images, default repository is https://hub.docker.com.
	TypeDocker = "docker"
	// TypeGem is a pkg:gem purl for Rubygems packages, default repository is https://rubygems.org.
	TypeGem = "gem"
	// TypeGeneric is a pkg:generic purl for plain, generic packages that do not fit anywhere else such as for "upstream-from-distro" packages.
	// in particular this is handy for a plain version control repository such as a bare git repo.
	TypeGeneric = "generic"
	// TypeGithub is a pkg:github purl for Github-based packages, default repository is https://github.com.
	TypeGithub = "github"
	// TypeGolang is a pkg:golang purl for Go packages, no default package repository.
	TypeGolang = "golang"
	// TypeHackage is a pkg:hackage purl for Haskell packages, default repository is https://hackage.haskell.org.
	TypeHackage = "hackage"
	// TypeHex is a pkg:hex purl for Hex packages, default repository is https://repo.hex.pm.
	TypeHex = "hex"
	// TypeMaven is a pkg:maven purl for Maven packages, default repository is https://repo.maven.apache.org/maven2.
	TypeMaven = "maven"
	// TypeNPM is a pkg:npm purl for Node NPM packages, default repository is https://registry.npmjs.org.
	TypeNPM = "npm"
	// TypeNuget is a pkg:nuget purl for NuGet .NET packages, default repository is https://www.nuget.org.
	TypeNuget = "nuget"
	// TypeOCI is a pkg:oci purl for all artifacts stored in registries that conform to the OCI Distribution Specification, including container images built by Docker and others, no canonical package repository for OCI artifacts.
	TypeOCI = "oci"
	// TypePub is a pkg:pub purl for Dart and Flutter packages, default repository is https://pub.dartlang.org.
	TypePub = "pub"
	// TypePyPi is a pkg:pypi purl for Python packages, default repository is https://pypi.python.org.
	TypePyPi = "pypi"
	// TypeRPM is a pkg:rpm purl for RPMs, no default package repository.
	TypeRPM = "rpm"
	// TypeSWID is a pkg:swid purl for ISO-IEC 19770-2 Software Identification (SWID) tags.
	TypeSWID = "swid"
	// TypeSwift is pkg:swift purl for Swift packages, no default package repository.
	TypeSwift = "swift"
)

// These are the candidate purl types as promoted in the spec,
// they may be changed.
// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#other-candidate-types-to-define
// NB(thxCode): we can view many candidates from the above references,
// recommend to support one, then add one.
var (
	// TypeAlpine is a pkg:alpine purl for Alpine Linux, default repository is https://dl-cdn.alpinelinux.org/alpine/.
	TypeAlpine = "alpine"
)

// Qualifier represents a single key=value qualifier in the package url
type Qualifier struct {
	Key   string
	Value string
}

func (q Qualifier) String() string {
	// A value must be a percent-encoded string
	return fmt.Sprintf("%s=%s", q.Key, url.PathEscape(q.Value))
}

// Qualifiers is a slice of key=value pairs, with order preserved as it appears
// in the package URL.
type Qualifiers []Qualifier

// QualifiersFromMap constructs a Qualifiers slice from a string map. To get a
// deterministic qualifier order (despite maps not providing any iteration order
// guarantees) the returned Qualifiers are sorted in increasing order of key.
func QualifiersFromMap(mm map[string]string) Qualifiers {
	q := Qualifiers{}

	for k, v := range mm {
		q = append(q, Qualifier{Key: k, Value: v})
	}

	// sort for deterministic qualifier order
	sort.Slice(q, func(i int, j int) bool { return q[i].Key < q[j].Key })

	return q
}

// Map converts a Qualifiers struct to a string map.
func (qq Qualifiers) Map() map[string]string {
	m := make(map[string]string)

	for i := 0; i < len(qq); i++ {
		k := qq[i].Key
		v := qq[i].Value
		m[k] = v
	}

	return m
}

func (qq Qualifiers) String() string {
	var kvPairs []string
	for _, q := range qq {
		kvPairs = append(kvPairs, q.String())
	}
	return strings.Join(kvPairs, "&")
}

// PackageURL is the struct representation of the parts that make a package url
type PackageURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers Qualifiers
	Subpath    string
}

// NewPackageURL creates a new PackageURL struct instance based on input
func NewPackageURL(purlType, namespace, name, version string,
	qualifiers Qualifiers, subpath string) *PackageURL {

	return &PackageURL{
		Type:       purlType,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
		Subpath:    subpath,
	}
}

func (p PackageURL) String() string {
	var purlBuilder strings.Builder

	// Start with the type and a colon
	purlBuilder.WriteString("pkg:")
	purlBuilder.WriteString(p.Type)
	purlBuilder.WriteString("/")

	// Add namespaces if provided
	if p.Namespace != "" {
		for _, ns := range strings.Split(p.Namespace, "/") {
			purlBuilder.WriteString(url.QueryEscape(typeAdjustNamespace(p.Type, ns)))
			purlBuilder.WriteString("/")
		}
	}

	// The name is always required and must be a percent-encoded string
	// Use url.QueryEscape instead of PathEscape, as it handles @ signs
	purlBuilder.WriteString(url.QueryEscape(typeAdjustName(p.Type, p.Name)))

	// If a version is provided, add it after the at symbol
	if ver := p.Version; ver != "" {
		// A name must be a percent-encoded string
		purlBuilder.WriteString("@")
		purlBuilder.WriteString(url.PathEscape(typeAdjustVersion(p.Type, ver)))
	}

	// If there are one or more key=value pairs, append on the package url
	if len(p.Qualifiers) != 0 {
		var qs = typeAdjustQualifiers(p.Type, p.Qualifiers)
		purlBuilder.WriteString("?")
		for i, q := range qs {
			purlBuilder.WriteString(q.Key)
			purlBuilder.WriteString("=")
			purlBuilder.WriteString(url.PathEscape(q.Value))
			if i < len(qs)-1 {
				purlBuilder.WriteString("&")
			}
		}
	}

	// Add a subpath if available
	if p.Subpath != "" {
		purlBuilder.WriteString("#")
		purlBuilder.WriteString(p.Subpath)
	}

	return purlBuilder.String()
}

// FromString parses a valid package url string into a PackageURL structure
func FromString(purl string) (PackageURL, error) {
	initialIndex := strings.Index(purl, "#")
	// Start with purl being stored in the remainder
	remainder := purl
	substring := ""
	if initialIndex != -1 {
		initialSplit := strings.SplitN(purl, "#", 2)
		remainder = initialSplit[0]
		rightSide := initialSplit[1]
		rightSide = strings.TrimLeft(rightSide, "/")
		rightSide = strings.TrimRight(rightSide, "/")
		var rightSides []string

		for _, item := range strings.Split(rightSide, "/") {
			item = strings.Replace(item, ".", "", -1)
			item = strings.Replace(item, "..", "", -1)
			if item != "" {
				i, err := url.PathUnescape(item)
				if err != nil {
					return PackageURL{}, fmt.Errorf("failed to unescape path: %s", err)
				}
				rightSides = append(rightSides, i)
			}
		}
		substring = strings.Join(rightSides, "/")
	}
	qualifiers := Qualifiers{}
	index := strings.LastIndex(remainder, "?")
	// If we don't have anything to split then return an empty result
	if index != -1 {
		qualifier := remainder[index+1:]
		for _, item := range strings.Split(qualifier, "&") {
			kv := strings.Split(item, "=")
			key := strings.ToLower(kv[0])
			key, err := url.PathUnescape(key)
			if err != nil {
				return PackageURL{}, fmt.Errorf("failed to unescape qualifier key: %s", err)
			}
			if !validQualifierKey(key) {
				return PackageURL{}, fmt.Errorf("invalid qualifier key: '%s'", key)
			}
			// TODO
			//  - If the `key` is `checksums`, split the `value` on ',' to create
			//    a list of `checksums`
			if kv[1] == "" {
				continue
			}
			value, err := url.PathUnescape(kv[1])
			if err != nil {
				return PackageURL{}, fmt.Errorf("failed to unescape qualifier value: %s", err)
			}
			qualifiers = append(qualifiers, Qualifier{key, value})
		}
		remainder = remainder[:index]
	}

	nextSplit := strings.SplitN(remainder, ":", 2)
	if len(nextSplit) != 2 || nextSplit[0] != "pkg" {
		return PackageURL{}, errors.New("scheme is missing")
	}
	// leading slashes after pkg: are to be ignored (pkg://maven is
	// equivalent to pkg:maven)
	remainder = strings.TrimLeft(nextSplit[1], "/")

	nextSplit = strings.SplitN(remainder, "/", 2)
	if len(nextSplit) != 2 {
		return PackageURL{}, errors.New("type is missing")
	}
	// purl type is case-insensitive, canonical form is lower-case
	purlType := strings.ToLower(nextSplit[0])
	remainder = nextSplit[1]

	index = strings.LastIndex(remainder, "/")
	name := typeAdjustName(purlType, remainder[index+1:])
	version := ""

	atIndex := strings.Index(name, "@")
	if atIndex != -1 {
		v, err := url.PathUnescape(name[atIndex+1:])
		if err != nil {
			return PackageURL{}, fmt.Errorf("failed to unescape purl version: %s", err)
		}
		version = typeAdjustVersion(purlType, v)

		unecapeName, err := url.PathUnescape(name[:atIndex])
		if err != nil {
			return PackageURL{}, fmt.Errorf("failed to unescape purl name: %s", err)
		}
		name = unecapeName
	}
	var namespaces []string

	if index != -1 {
		remainder = remainder[:index]

		for _, item := range strings.Split(remainder, "/") {
			if item != "" {
				unescaped, err := url.PathUnescape(item)
				if err != nil {
					return PackageURL{}, fmt.Errorf("failed to unescape path: %s", err)
				}
				namespaces = append(namespaces, unescaped)
			}
		}
	}
	namespace := strings.Join(namespaces, "/")
	namespace = typeAdjustNamespace(purlType, namespace)

	// Fail if name is empty at this point
	if name == "" {
		return PackageURL{}, errors.New("name is required")
	}

	err := validCustomRules(purlType, name, namespace, version, qualifiers)
	if err != nil {
		return PackageURL{}, err
	}

	return PackageURL{
		Type:       purlType,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: typeAdjustQualifiers(purlType, qualifiers),
		Subpath:    substring,
	}, nil
}

// Make any purl type-specific adjustments to the parsed namespace.
// See https://github.com/package-url/purl-spec#known-purl-types
func typeAdjustNamespace(purlType, ns string) string {
	switch purlType {
	case TypeBitbucket, TypeDebian, TypeGithub, TypeGolang, TypeNPM, TypeRPM, TypeHex:
		return strings.ToLower(ns)
	}
	return ns
}

// Make any purl type-specific adjustments to the parsed name.
// See https://github.com/package-url/purl-spec#known-purl-types
func typeAdjustName(purlType, name string) string {
	switch purlType {
	case TypeBitbucket, TypeDebian, TypeGithub, TypeGolang, TypeNPM, TypeHex, TypeOCI:
		return strings.ToLower(name)
	case TypePyPi:
		return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	}
	return name
}

// Make any purl type-specific adjustments to the parsed version.
// See https://github.com/package-url/purl-spec#known-purl-types
func typeAdjustVersion(purlType, ver string) string {
	switch purlType {
	case TypeOCI:
		return strings.ToLower(ver)
	}
	return ver
}

// Make any purl type-specific adjustments to the parsed qualifiers.
// See https://github.com/package-url/purl-spec#known-purl-types
func typeAdjustQualifiers(purlType string, qualifiers Qualifiers) Qualifiers {
	switch purlType {
	case TypeSWID:
		for i := range qualifiers {
			if qualifiers[i].Key == "tag_id" {
				var value = qualifiers[i].Value
				var _, err = uuid.Parse(value)
				if err == nil {
					qualifiers[i].Value = strings.ToLower(value)
				}
			}
		}
	}
	return qualifiers
}

// validQualifierKey validates a qualifierKey against our QualifierKeyPattern.
func validQualifierKey(key string) bool {
	return QualifierKeyPattern.MatchString(key)
}

// validCustomRules evaluates additional rules for each package url type, as specified in the package-url specification.
// On success, it returns nil. On failure, a descriptive error will be returned.
func validCustomRules(purlType, name, ns, version string, qualifiers Qualifiers) error {
	q := qualifiers.Map()
	switch purlType {
	case TypeConan:
		if ns != "" {
			if val, ok := q["channel"]; ok {
				if val == "" {
					return errors.New("the qualifier channel must be not empty if namespace is present")
				}
			} else {
				return errors.New("channel qualifier does not exist")
			}
		} else {
			if val, ok := q["channel"]; ok {
				if val != "" {
					return errors.New("namespace is required if channel is non empty")
				}
			}
		}
	case TypeSwift:
		if ns == "" {
			return errors.New("namespace is required")
		}
		if version == "" {
			return errors.New("version is required")
		}
	case TypeCran:
		if version == "" {
			return errors.New("version is required")
		}
	}
	return nil
}

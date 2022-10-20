package cvss

import (
	"strings"

	"github.com/seal-io/meta-api/cvss/compatible"
	"github.com/seal-io/meta-api/cvss/cvssv2"
	"github.com/seal-io/meta-api/cvss/cvssv3"
)

// ShouldParse likes Parse but without error returning.
func ShouldParse(s string) compatible.Vector {
	var p, _ = Parse(s)
	return p
}

// Parse parses Vector from CVSS vector string.
func Parse(s string) (compatible.Vector, error) {
	var prefix = strings.SplitN(s, "/", 2)[0]
	switch prefix {
	case "CVSS:3.0", "CVSS:3.1":
		return cvssv3.Parse(s)
	default:
		return cvssv2.Parse(s)
	}
}

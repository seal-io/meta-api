package ssvc

import (
	"fmt"
	"strings"

	"github.com/seal-io/meta-api/ssvc/compatible"
	"github.com/seal-io/meta-api/ssvc/ssvc2"
)

// ShouldParse likes Parse but without error returning.
func ShouldParse(s string) compatible.Vector {
	var p, _ = Parse(s)
	return p
}

// Parse parses Vector from SSVC vector string.
func Parse(s string) (compatible.Vector, error) {
	var prefix = strings.SplitN(s, "/", 2)[0]
	switch prefix {
	case "SSVCv2":
		return ssvc2.Parse(s)
	}
	return nil, fmt.Errorf("invalid SSVC vector: %s", s)
}

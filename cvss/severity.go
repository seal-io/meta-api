package cvss

import (
	"strings"

	"github.com/seal-io/meta-api/cvss/cvssv3"
)

// GetSeverityNumber returns number of the given severity,
// it doesn't return the actual score of the severity but instead of a numeric value,
// which can be used for comparing.
func GetSeverityNumber(s string) int {
	s = strings.ToUpper(s)
	if s != "" {
		s = s[:1]
	}
	switch s {
	case "C":
		return 4
	case "H":
		return 3
	case "M":
		return 2
	case "L":
		return 1
	default:
		return 0
	}
}

// CompareSeverity returns an integer comparing two severity.
// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
func CompareSeverity(v, w string) int {
	var vs = GetSeverityNumber(v)
	var ws = GetSeverityNumber(w)
	var s = vs - ws
	if s > 0 {
		return +1
	}
	if s < 0 {
		return -1
	}
	return 0
}

// GetScoreExampleBySeverity returns the CVSS(V3) score example by the given severity,
// which is keeping the highest exploitability sub score in cater to the severity.
func GetScoreExampleBySeverity(s string) (vectorString string, baseScore float64, impactScore float64, exploitabilityScore float64) {
	return cvssv3.GetScoreExampleBySeverity(s)
}

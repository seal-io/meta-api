package cvssv2

import "strings"

type Severity = string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
)

// GetSeverityByScore returns severity by the given score,
// based on https://nvd.nist.gov/vuln-metrics/cvss.
func GetSeverityByScore(s float64) Severity {
	if s >= 7 {
		return SeverityHigh
	} else if s >= 4 {
		return SeverityMedium
	}
	return SeverityLow
}

// GetScoreExampleBySeverity returns the score example by the given severity,
// which is keeping the highest exploitability sub score in cater to the severity.
func GetScoreExampleBySeverity(s string) (vectorString string, baseScore float64, impactScore float64, exploitabilityScore float64) {
	// NB(thxCode): usually, an attack is combinatorial,
	// a vulnerability has lower score but highest exploitability can be used for starting.
	s = strings.ToUpper(s)
	if s != "" {
		s = s[:1]
	}
	switch s {
	case "H":
		vectorString = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
		baseScore = 7.5
		impactScore = 6.4
		exploitabilityScore = 10.0
	case "M":
		vectorString = "AV:N/AC:L/Au:N/C:P/I:N/A:N"
		baseScore = 5.0
		impactScore = 2.9
		exploitabilityScore = 10.0
	default:
		vectorString = "AV:N/AC:M/Au:S/C:P/I:N/A:N"
		baseScore = 3.5
		impactScore = 2.9
		exploitabilityScore = 6.8
	}
	return
}

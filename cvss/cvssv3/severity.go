package cvssv3

import "strings"

type Severity = string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// GetSeverityByScore returns severity by the given score,
// based on https://www.first.org/cvss/specification-document#Qualitative-Severity-Rating-Scale.
func GetSeverityByScore(s float64) Severity {
	if s >= 9 {
		return SeverityCritical
	} else if s >= 7 {
		return SeverityHigh
	} else if s >= 4 {
		return SeverityMedium
	} else if s > 0 {
		return SeverityLow
	}
	return SeverityNone
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
	case "C":
		vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
		baseScore = 9.1
		impactScore = 5.2
		exploitabilityScore = 3.9
	case "H":
		vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
		baseScore = 8.2
		impactScore = 4.2
		exploitabilityScore = 3.9
	case "M":
		vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
		baseScore = 6.5
		impactScore = 2.5
		exploitabilityScore = 3.9
	case "L":
		vectorString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
		baseScore = 3.7
		impactScore = 1.4
		exploitabilityScore = 2.2
	default:
		vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
		baseScore = 0
		impactScore = 0
		exploitabilityScore = 3.9
	}
	return
}

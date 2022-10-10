package cvssv3

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

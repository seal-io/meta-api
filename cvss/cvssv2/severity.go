package cvssv2

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

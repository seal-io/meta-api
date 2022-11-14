package ssvc2

import "github.com/seal-io/meta-api/cvss/cvssv3"

// GetCVSSScoreAndSeverityByPriority returns CVSS(V3) score and severity by the given priority.
func GetCVSSScoreAndSeverityByPriority(p Priority) (float64, string) {
	switch p {
	case PriorityImmediate:
		return 9.5, cvssv3.SeverityCritical
	case PriorityOutOfCycle:
		return 8, cvssv3.SeverityHigh
	case PriorityScheduled:
		return 5.5, cvssv3.SeverityMedium
	case PriorityDefer:
		return 2.0, cvssv3.SeverityLow
	default:
		return 0, cvssv3.SeverityNone
	}
}

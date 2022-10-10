package cvss

import (
	"strings"

	"github.com/seal-io/meta-api/cvss/cvssv2"
	"github.com/seal-io/meta-api/cvss/cvssv3"
)

// Vector holds the score calculating function of CVSS vector.
type Vector interface {
	// RawImpactScore return the raw impact score of this CVSS vector.
	RawImpactScore(modified bool) float64
	// RawExploitabilityScore return the raw exploitability score of this CVSS vector.
	RawExploitabilityScore(modified bool) float64
	// ImpactScore returns the impact score of this CVSS vector.
	ImpactScore() float64
	// ExploitabilityScore returns the exploitability score of this CVSS vector.
	ExploitabilityScore() float64
	// BaseScore returns the base score of this CVSS vector.
	BaseScore() float64
	// BaseSeverity returns the base severity of this CVSS vector.
	BaseSeverity() string
	// BaseScoreAndSeverity returns the base score and severity of this CVSS vector.
	BaseScoreAndSeverity() (score float64, severity string)
	// TemporalScore returns the temporal score of this CVSS vector.
	TemporalScore(baseScore ...float64) float64
	// TemporalSeverity returns the temporal severity of this CVSS vector.
	TemporalSeverity(baseScore ...float64) string
	// TemporalScoreAndSeverity returns the temporal score and severity of this CVSS vector.
	TemporalScoreAndSeverity(baseScore ...float64) (score float64, severity string)
	// EnvironmentalScore returns the environmental score of this CVSS vector.
	EnvironmentalScore() float64
	// EnvironmentalSeverity returns the environmental severity of this CVSS vector.
	EnvironmentalSeverity() string
	// EnvironmentalScoreAndSeverity returns the environmental score and severity of this CVSS vector.
	EnvironmentalScoreAndSeverity() (score float64, severity string)
	// ScoreAndSeverity returns the score and severity of this CVSS vector, including
	// - BaseScore and BaseSeverity
	// - TemporalScore and TemporalSeverity
	// - EnvironmentalScore and EnvironmentalSeverity
	ScoreAndSeverity() (bs float64, bsv string, ts float64, tsv string, es float64, esv string)
	// GetVersion returns the cvss version of this CVSS vector.
	GetVersion() string
}

// ShouldParse likes Parse but without error returning.
func ShouldParse(s string) Vector {
	var p, _ = Parse(s)
	return p
}

// Parse parses Vector from CVSS vector string.
func Parse(s string) (Vector, error) {
	var prefix = strings.SplitN(s, "/", 2)[0]
	switch prefix {
	case "CVSS:3.0", "CVSS:3.1":
		return cvssv3.Parse(s)
	default:
		return cvssv2.Parse(s)
	}
}

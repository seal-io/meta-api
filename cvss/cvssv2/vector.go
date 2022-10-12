package cvssv2

import (
	"fmt"
	"math"
	"strings"
)

// DefaultVector returns a default definition of CVSS(V2) vector.
func DefaultVector() Vector {
	return Vector{
		BasicMetrics: BasicMetrics{
			AccessVector:          AccessVectorLocal,
			AccessComplexity:      AccessComplexityHigh,
			Authentication:        AuthenticationMultiple,
			ConfidentialityImpact: ConfidentialityImpactNone,
			IntegrityImpact:       IntegrityImpactNone,
			AvailabilityImpact:    AvailabilityImpactNone,
		},
		TemporalMetrics: TemporalMetrics{
			Exploitability:   ExploitabilityNotDefined,
			RemediationLevel: RemediationLevelNotDefined,
			ReportConfidence: ReportConfidenceNotDefined,
		},
		EnvironmentalMetrics: EnvironmentalMetrics{
			CollateralDamagePotential:  CollateralDamagePotentialNotDefined,
			TargetDistribution:         TargetDistributionNotDefined,
			ConfidentialityRequirement: SecurityRequirementNotDefined,
			IntegrityRequirement:       SecurityRequirementNotDefined,
			AvailabilityRequirement:    SecurityRequirementNotDefined,
		},
	}
}

// ShouldParse likes Parse but without error returning.
func ShouldParse(s string) Vector {
	var p, _ = Parse(s)
	return p
}

// Parse parses Vector from CVSS(V2) vector string.
func Parse(s string) (Vector, error) {
	const mandatorySize = 6
	s = strings.TrimSpace(s)
	var v = DefaultVector()
	var parts = strings.Split(s, "/")
	if len(parts) < mandatorySize {
		return Vector{}, fmt.Errorf("illegal CVSS(V2) vector: %s", s)
	}
	for i, part := range parts {
		var kv = strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return Vector{}, fmt.Errorf("incomplete CVSS(V2) vector: %s", s)
		}
		var mn = strings.TrimSpace(kv[0])
		if mn == "" {
			return Vector{}, fmt.Errorf("incomplete CVSS(V2) vector: %s", s)
		}
		var mv = strings.TrimSpace(kv[1])
		if mv == "" {
			return Vector{}, fmt.Errorf("incomplete CVSS(V2) vector: %s", s)
		}
		switch mn {
		// base metrics
		case "AV":
			v.AccessVector = AccessVector(mv)
			if !v.AccessVector.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V2) vector: %s", mn, s)
			}
		case "AC":
			v.AccessComplexity = AccessComplexity(mv)
			if !v.AccessComplexity.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V2) vector: %s", mn, s)
			}
		case "Au":
			v.Authentication = Authentication(mv)
			if !v.Authentication.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V2) vector: %s", mn, s)
			}
		case "C":
			v.ConfidentialityImpact = ConfidentialityImpact(mv)
			if !v.ConfidentialityImpact.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V2) vector: %s", mn, s)
			}
		case "I":
			v.IntegrityImpact = IntegrityImpact(mv)
			if !v.IntegrityImpact.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V2) vector: %s", mn, s)
			}
		case "A":
			v.AvailabilityImpact = AvailabilityImpact(mv)
			if !v.AvailabilityImpact.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V2) vector: %s", mn, s)
			}
		default:
			if i < mandatorySize {
				return Vector{}, fmt.Errorf("'%s' is not mandatory metric in CVSS(V2) vector: %s", mn, s)
			}
			switch mn {
			default:
				return Vector{}, fmt.Errorf("unknown metric '%s' in CVSS(V2) vector: %s", mn, s)
			// temporal metrics
			case "E":
				v.Exploitability = Exploitability(mv)
			case "RL":
				v.RemediationLevel = RemediationLevel(mv)
			case "RC":
				v.ReportConfidence = ReportConfidence(mv)
			// environmental metrics
			case "CDP":
				v.CollateralDamagePotential = CollateralDamagePotential(mv)
			case "TD":
				v.TargetDistribution = TargetDistribution(mv)
			case "CR":
				v.ConfidentialityRequirement = SecurityRequirement(mv)
			case "IR":
				v.IntegrityRequirement = SecurityRequirement(mv)
			case "AR":
				v.AvailabilityRequirement = SecurityRequirement(mv)
			}
		}
	}
	return v, nil
}

// Vector holds the metrics vector of CVSS(V2).
type Vector struct {
	BasicMetrics
	TemporalMetrics
	EnvironmentalMetrics
}

// RawImpactScore return the raw impact score of this CVSS(V2) vector.
func (in Vector) RawImpactScore(modified bool) float64 {
	var c = in.getConfidentialityImpact()
	var i = in.getIntegrityImpact()
	var a = in.getAvailabilityImpact()
	if modified {
		var cr = in.getConfidentialityRequirement()
		var ir = in.getIntegrityRequirement()
		var ar = in.getAvailabilityRequirement()
		return math.Min(10, 10.41*(1-(1-c*cr)*(1-i*ir)*(1-a*ar)))
	}
	return 10.41 * (1 - (1-c)*(1-i)*(1-a))
}

// RawExploitabilityScore return the raw exploitability score of this CVSS(V2) vector.
func (in Vector) RawExploitabilityScore(modified bool) float64 {
	var av = in.getAccessVector()
	var ac = in.getAccessComplexity()
	var au = in.getAuthentication()
	return 20 * av * ac * au
}

// ImpactScore returns the impact score of this CVSS(V2) vector.
func (in Vector) ImpactScore() float64 {
	return round(in.RawImpactScore(false))
}

// ExploitabilityScore returns the exploitability score of this CVSS(V2) vector.
func (in Vector) ExploitabilityScore() float64 {
	return round(in.RawExploitabilityScore(false))
}

// BaseScore returns the base score of this CVSS(V2) vector.
func (in Vector) BaseScore() float64 {
	var i = in.RawImpactScore(false)
	if i <= 0 {
		return 0.0
	}
	var e = in.RawExploitabilityScore(false)
	return round(((0.6 * i) + (0.4 * e) - 1.5) * 1.176)
}

// BaseSeverity returns the base severity of this CVSS(V2) vector.
func (in Vector) BaseSeverity() string {
	return GetSeverityByScore(in.BaseScore())
}

// BaseScoreAndSeverity returns the base score and severity of this CVSS(V2) vector.
func (in Vector) BaseScoreAndSeverity() (score float64, severity string) {
	score = in.BaseScore()
	severity = GetSeverityByScore(score)
	return
}

// TemporalScore returns the temporal score of this CVSS(V2) vector.
func (in Vector) TemporalScore(baseScore ...float64) float64 {
	var bs float64
	if len(baseScore) == 0 {
		bs = in.BaseScore()
	} else {
		bs = baseScore[0]
	}
	var exp = in.getExploitability()
	var rl = in.getRemediationLevel()
	var rc = in.getReportConfidence()
	return round(bs * exp * rl * rc)
}

// TemporalSeverity returns the temporal severity of this CVSS(V2) vector.
func (in Vector) TemporalSeverity(baseScore ...float64) string {
	return GetSeverityByScore(in.TemporalScore(baseScore...))
}

// TemporalScoreAndSeverity returns the temporal score and severity of this CVSS(V2) vector.
func (in Vector) TemporalScoreAndSeverity(baseScore ...float64) (score float64, severity string) {
	score = in.TemporalScore(baseScore...)
	severity = GetSeverityByScore(score)
	return
}

// EnvironmentalScore returns the environmental score of this CVSS(V2) vector.
func (in Vector) EnvironmentalScore() float64 {
	var i = in.RawImpactScore(true)
	if i <= 0 {
		return 0.0
	}
	var e = in.RawExploitabilityScore(true)
	var bs = round(((0.6 * i) + (0.4 * e) - 1.5) * 1.176)

	var exp = in.getExploitability()
	var rl = in.getRemediationLevel()
	var rc = in.getReportConfidence()
	var t = bs * exp * rl * rc

	var td = in.getTargetDistribution()
	var cdp = in.getCollateralDamagePotential()
	return round((t + (10-t)*cdp) * td)
}

// EnvironmentalSeverity returns the environmental severity of this CVSS(V2) vector.
func (in Vector) EnvironmentalSeverity() string {
	return GetSeverityByScore(in.EnvironmentalScore())
}

// EnvironmentalScoreAndSeverity returns the environmental score and severity of this CVSS(V2) vector.
func (in Vector) EnvironmentalScoreAndSeverity() (score float64, severity string) {
	score = in.EnvironmentalScore()
	severity = GetSeverityByScore(score)
	return
}

// ScoreAndSeverity returns the score and severity of this CVSS(V2) vector, including
// - BaseScore and BaseSeverity
// - TemporalScore and TemporalSeverity
// - EnvironmentalScore and EnvironmentalSeverity
func (in Vector) ScoreAndSeverity() (bs float64, bsv string, ts float64, tsv string, es float64, esv string) {
	bs, bsv = in.BaseScoreAndSeverity()
	ts, tsv = in.TemporalScoreAndSeverity(bs)
	es, esv = in.EnvironmentalScoreAndSeverity()
	return
}

// GetVersion returns the cvss version of this CVSS(V2) vector.
func (in Vector) GetVersion() string {
	return "2.0"
}

// String returns the string format of this CVSS(V2) vector.
func (in Vector) String() string {
	var c = DefaultVector().Override(in)
	var sb strings.Builder

	// base metrics
	sb.WriteString("AV:")
	sb.WriteString(string(c.AccessVector))
	sb.WriteString("/")
	sb.WriteString("AC:")
	sb.WriteString(string(c.AccessComplexity))
	sb.WriteString("/")
	sb.WriteString("Au:")
	sb.WriteString(string(c.Authentication))
	sb.WriteString("/")
	sb.WriteString("C:")
	sb.WriteString(string(c.ConfidentialityImpact))
	sb.WriteString("/")
	sb.WriteString("I:")
	sb.WriteString(string(c.IntegrityImpact))
	sb.WriteString("/")
	sb.WriteString("A:")
	sb.WriteString(string(c.AvailabilityImpact))
	// temporal metrics
	if c.Exploitability != ExploitabilityNotDefined {
		sb.WriteString("/")
		sb.WriteString("E:")
		sb.WriteString(string(c.Exploitability))
	}
	if c.RemediationLevel != RemediationLevelNotDefined {
		sb.WriteString("/")
		sb.WriteString("RL:")
		sb.WriteString(string(c.RemediationLevel))
	}
	if c.ReportConfidence != ReportConfidenceNotDefined {
		sb.WriteString("/")
		sb.WriteString("RC:")
		sb.WriteString(string(c.ReportConfidence))
	}
	// environmental metrics
	if c.CollateralDamagePotential != CollateralDamagePotentialNotDefined {
		sb.WriteString("/")
		sb.WriteString("CDP:")
		sb.WriteString(string(c.CollateralDamagePotential))
	}
	if c.TargetDistribution != TargetDistributionNotDefined {
		sb.WriteString("/")
		sb.WriteString("TD:")
		sb.WriteString(string(c.TargetDistribution))
	}
	if c.ConfidentialityRequirement != SecurityRequirementNotDefined {
		sb.WriteString("/")
		sb.WriteString("CR:")
		sb.WriteString(string(c.ConfidentialityRequirement))
	}
	if c.IntegrityRequirement != SecurityRequirementNotDefined {
		sb.WriteString("/")
		sb.WriteString("IR:")
		sb.WriteString(string(c.IntegrityRequirement))
	}
	if c.AvailabilityRequirement != SecurityRequirementNotDefined {
		sb.WriteString("/")
		sb.WriteString("AR:")
		sb.WriteString(string(c.AvailabilityRequirement))
	}

	return sb.String()
}

// Override merges the valued metrics of the given Vector.
func (in Vector) Override(v Vector) (out Vector) {
	out = in

	// basic metrics
	var bm = v.BasicMetrics
	if bm.AccessVector != "" {
		out.AccessVector = bm.AccessVector
	}
	if bm.AccessComplexity != "" {
		out.AccessComplexity = bm.AccessComplexity
	}
	if bm.Authentication != "" {
		out.Authentication = bm.Authentication
	}
	if bm.ConfidentialityImpact != "" {
		out.ConfidentialityImpact = bm.ConfidentialityImpact
	}
	if bm.IntegrityImpact != "" {
		out.IntegrityImpact = bm.IntegrityImpact
	}
	if bm.AvailabilityImpact != "" {
		out.AvailabilityImpact = bm.AvailabilityImpact
	}
	// temporal metrics
	var tm = v.TemporalMetrics
	if tm.Exploitability != "" {
		out.Exploitability = tm.Exploitability
	}
	if tm.RemediationLevel != "" {
		out.RemediationLevel = tm.RemediationLevel
	}
	if tm.ReportConfidence != "" {
		out.ReportConfidence = tm.ReportConfidence
	}
	// environment metrics
	var em = v.EnvironmentalMetrics
	if em.CollateralDamagePotential != "" {
		out.CollateralDamagePotential = em.CollateralDamagePotential
	}
	if em.TargetDistribution != "" {
		out.TargetDistribution = em.TargetDistribution
	}
	if em.ConfidentialityRequirement != "" {
		out.ConfidentialityRequirement = em.ConfidentialityRequirement
	}
	if em.IntegrityRequirement != "" {
		out.IntegrityRequirement = em.IntegrityRequirement
	}
	if em.AvailabilityRequirement != "" {
		out.AvailabilityRequirement = em.AvailabilityRequirement
	}

	return
}

// IsZero returns true if this CVSS(V2) vector is empty,
// DefaultVector is also an empty vector.
func (in Vector) IsZero() bool {
	return in == DefaultVector() || in == Vector{}
}

// types of basic metrics.
type (
	BasicMetrics struct {
		AccessVector
		AccessComplexity
		Authentication
		ConfidentialityImpact
		IntegrityImpact
		AvailabilityImpact
	}

	AccessVector          string
	AccessComplexity      string
	Authentication        string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
)

// constants of basic metrics.
const (
	AccessVectorLocal           AccessVector = "L"
	AccessVectorAdjacentNetwork AccessVector = "A"
	AccessVectorNetwork         AccessVector = "N"

	AccessComplexityHigh   AccessComplexity = "H"
	AccessComplexityMedium AccessComplexity = "M"
	AccessComplexityLow    AccessComplexity = "L"

	AuthenticationMultiple Authentication = "M"
	AuthenticationSingle   Authentication = "S"
	AuthenticationNone     Authentication = "N"

	ConfidentialityImpactNone     ConfidentialityImpact = "N"
	ConfidentialityImpactPartial  ConfidentialityImpact = "P"
	ConfidentialityImpactComplete ConfidentialityImpact = "C"

	IntegrityImpactNone     IntegrityImpact = "N"
	IntegrityImpactPartial  IntegrityImpact = "P"
	IntegrityImpactComplete IntegrityImpact = "C"

	AvailabilityImpactNone     AvailabilityImpact = "N"
	AvailabilityImpactPartial  AvailabilityImpact = "P"
	AvailabilityImpactComplete AvailabilityImpact = "C"
)

func (in AccessVector) isDefined() bool {
	switch in {
	default:
		return false
	case AccessVectorLocal:
	case AccessVectorAdjacentNetwork:
	case AccessVectorNetwork:
	}
	return true
}

func (in AccessComplexity) isDefined() bool {
	switch in {
	default:
		return false
	case AccessComplexityHigh:
	case AccessComplexityMedium:
	case AccessComplexityLow:
	}
	return true
}

func (in Authentication) isDefined() bool {
	switch in {
	default:
		return false
	case AuthenticationMultiple:
	case AuthenticationSingle:
	case AuthenticationNone:
	}
	return true
}

func (in ConfidentialityImpact) isDefined() bool {
	switch in {
	default:
		return false
	case ConfidentialityImpactNone:
	case ConfidentialityImpactPartial:
	case ConfidentialityImpactComplete:
	}
	return true
}

func (in IntegrityImpact) isDefined() bool {
	switch in {
	default:
		return false
	case IntegrityImpactNone:
	case IntegrityImpactPartial:
	case IntegrityImpactComplete:
	}
	return true
}

func (in AvailabilityImpact) isDefined() bool {
	switch in {
	default:
		return false
	case AvailabilityImpactNone:
	case AvailabilityImpactPartial:
	case AvailabilityImpactComplete:
	}
	return true
}

func (in BasicMetrics) getAccessVector() float64 {
	switch in.AccessVector {
	default:
		fallthrough
	case AccessVectorLocal:
		return 0.395
	case AccessVectorAdjacentNetwork:
		return 0.646
	case AccessVectorNetwork:
		return 1
	}
}

func (in BasicMetrics) getAccessComplexity() float64 {
	switch in.AccessComplexity {
	default:
		fallthrough
	case AccessComplexityHigh:
		return 0.35
	case AccessComplexityMedium:
		return 0.61
	case AccessComplexityLow:
		return 0.71
	}
}

func (in BasicMetrics) getAuthentication() float64 {
	switch in.Authentication {
	default:
		fallthrough
	case AuthenticationMultiple:
		return 0.45
	case AuthenticationSingle:
		return 0.56
	case AuthenticationNone:
		return 0.704
	}
}

func (in BasicMetrics) getConfidentialityImpact() float64 {
	switch in.ConfidentialityImpact {
	default:
		fallthrough
	case ConfidentialityImpactNone:
		return 0
	case ConfidentialityImpactPartial:
		return 0.275
	case ConfidentialityImpactComplete:
		return 0.66
	}
}

func (in BasicMetrics) getIntegrityImpact() float64 {
	switch in.IntegrityImpact {
	default:
		fallthrough
	case IntegrityImpactNone:
		return 0
	case IntegrityImpactPartial:
		return 0.275
	case IntegrityImpactComplete:
		return 0.66
	}
}

func (in BasicMetrics) getAvailabilityImpact() float64 {
	switch in.AvailabilityImpact {
	default:
		fallthrough
	case AvailabilityImpactNone:
		return 0
	case AvailabilityImpactPartial:
		return 0.275
	case AvailabilityImpactComplete:
		return 0.66
	}
}

// types of temporal metrics.
type (
	TemporalMetrics struct {
		Exploitability
		RemediationLevel
		ReportConfidence
	}

	Exploitability   string
	RemediationLevel string
	ReportConfidence string
)

// constants of temporal metrics.
const (
	ExploitabilityNotDefined     Exploitability = "ND"
	ExploitabilityUnproven       Exploitability = "U"
	ExploitabilityProofOfConcept Exploitability = "POC"
	ExploitabilityFunctional     Exploitability = "F"
	ExploitabilityHigh           Exploitability = "H"

	RemediationLevelNotDefined   RemediationLevel = "ND"
	RemediationLevelOfficialFix  RemediationLevel = "OF"
	RemediationLevelTemporaryFix RemediationLevel = "TF"
	RemediationLevelWorkaround   RemediationLevel = "W"
	RemediationLevelUnavailable  RemediationLevel = "U"

	ReportConfidenceNotDefined     ReportConfidence = "ND"
	ReportConfidenceUnconfirmed    ReportConfidence = "UC"
	ReportConfidenceUncorroborated ReportConfidence = "UR"
	ReportConfidenceConfirmed      ReportConfidence = "C"
)

func (in TemporalMetrics) getExploitability() float64 {
	switch in.Exploitability {
	default:
		fallthrough
	case ExploitabilityNotDefined:
		return 1
	case ExploitabilityUnproven:
		return 0.85
	case ExploitabilityProofOfConcept:
		return 0.9
	case ExploitabilityFunctional:
		return 0.95
	case ExploitabilityHigh:
		return 1
	}
}

func (in TemporalMetrics) getRemediationLevel() float64 {
	switch in.RemediationLevel {
	default:
		fallthrough
	case RemediationLevelNotDefined:
		return 1
	case RemediationLevelOfficialFix:
		return 0.87
	case RemediationLevelTemporaryFix:
		return 0.90
	case RemediationLevelWorkaround:
		return 0.95
	case RemediationLevelUnavailable:
		return 1
	}
}

func (in TemporalMetrics) getReportConfidence() float64 {
	switch in.ReportConfidence {
	default:
		fallthrough
	case ReportConfidenceNotDefined:
		return 1
	case ReportConfidenceUnconfirmed:
		return 0.90
	case ReportConfidenceUncorroborated:
		return 0.95
	case ReportConfidenceConfirmed:
		return 1
	}
}

// types of environmental metrics.
type (
	EnvironmentalMetrics struct {
		CollateralDamagePotential
		TargetDistribution
		ConfidentialityRequirement SecurityRequirement
		IntegrityRequirement       SecurityRequirement
		AvailabilityRequirement    SecurityRequirement
	}

	CollateralDamagePotential string
	TargetDistribution        string
	SecurityRequirement       string
)

// constants of environmental metrics.
const (
	CollateralDamagePotentialNotDefined CollateralDamagePotential = "ND"
	CollateralDamagePotentialNone       CollateralDamagePotential = "N"
	CollateralDamagePotentialLow        CollateralDamagePotential = "L"
	CollateralDamagePotentialLowMedium  CollateralDamagePotential = "LM"
	CollateralDamagePotentialMediumHigh CollateralDamagePotential = "MH"
	CollateralDamagePotentialHigh       CollateralDamagePotential = "H"

	TargetDistributionNotDefined TargetDistribution = "ND"
	TargetDistributionNone       TargetDistribution = "N"
	TargetDistributionLow        TargetDistribution = "L"
	TargetDistributionMedium     TargetDistribution = "M"
	TargetDistributionHigh       TargetDistribution = "H"

	SecurityRequirementNotDefined SecurityRequirement = "ND"
	SecurityRequirementLow        SecurityRequirement = "L"
	SecurityRequirementMedium     SecurityRequirement = "M"
	SecurityRequirementHigh       SecurityRequirement = "H"
)

func (in EnvironmentalMetrics) getCollateralDamagePotential() float64 {
	switch in.CollateralDamagePotential {
	default:
		fallthrough
	case CollateralDamagePotentialNotDefined:
		return 0
	case CollateralDamagePotentialNone:
		return 0
	case CollateralDamagePotentialLow:
		return 0.1
	case CollateralDamagePotentialLowMedium:
		return 0.3
	case CollateralDamagePotentialMediumHigh:
		return 0.4
	case CollateralDamagePotentialHigh:
		return 0.5
	}
}

func (in EnvironmentalMetrics) getTargetDistribution() float64 {
	switch in.TargetDistribution {
	default:
		fallthrough
	case TargetDistributionNotDefined:
		return 1
	case TargetDistributionNone:
		return 0
	case TargetDistributionLow:
		return 0.25
	case TargetDistributionMedium:
		return 0.75
	case TargetDistributionHigh:
		return 1
	}
}

func (in EnvironmentalMetrics) getConfidentialityRequirement() float64 {
	switch in.ConfidentialityRequirement {
	default:
		fallthrough
	case SecurityRequirementNotDefined:
		return 1
	case SecurityRequirementLow:
		return 0.5
	case SecurityRequirementMedium:
		return 1
	case SecurityRequirementHigh:
		return 1.51
	}
}

func (in EnvironmentalMetrics) getIntegrityRequirement() float64 {
	switch in.IntegrityRequirement {
	default:
		fallthrough
	case SecurityRequirementNotDefined:
		return 1
	case SecurityRequirementLow:
		return 0.5
	case SecurityRequirementMedium:
		return 1
	case SecurityRequirementHigh:
		return 1.51
	}
}

func (in EnvironmentalMetrics) getAvailabilityRequirement() float64 {
	switch in.AvailabilityRequirement {
	default:
		fallthrough
	case SecurityRequirementNotDefined:
		return 1
	case SecurityRequirementLow:
		return 0.5
	case SecurityRequirementMedium:
		return 1
	case SecurityRequirementHigh:
		return 1.51
	}
}

func round(f float64) float64 {
	if f <= 0 {
		return 0.0
	}
	return math.Round(f*10) / 10
}

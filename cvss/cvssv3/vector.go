package cvssv3

import (
	"fmt"
	"math"
	"strings"

	"github.com/seal-io/meta-api/cvss/compatible"
)

// DefaultVector returns a default definition of CVSS(V3) vector.
func DefaultVector() Vector {
	return Vector{
		Version: Version31,
		BasicMetrics: BasicMetrics{
			AttackVector:          AttackVectorPhysical,
			AttackComplexity:      AttackComplexityHigh,
			PrivilegesRequired:    PrivilegesRequiredHigh,
			UserInteraction:       UserInteractionRequired,
			Scope:                 ScopeUnchanged,
			ConfidentialityImpact: ConfidentialityImpactNone,
			IntegrityImpact:       IntegrityImpactNone,
			AvailabilityImpact:    AvailabilityImpactNone,
		},
		TemporalMetrics: TemporalMetrics{
			ExploitCodeMaturity: ExploitCodeMaturityNotDefined,
			RemediationLevel:    RemediationLevelNotDefined,
			ReportConfidence:    ReportConfidenceNotDefined,
		},
		EnvironmentalMetrics: EnvironmentalMetrics{
			ConfidentialityRequirement: SecurityRequirementNotDefined,
			IntegrityRequirement:       SecurityRequirementNotDefined,
			AvailabilityRequirement:    SecurityRequirementNotDefined,
			ModifiedAttackVector:       AttackVectorNotDefined,
			ModifiedAttackComplexity:   AttackComplexityNotDefined,
			ModifiedPrivilegesRequired: PrivilegesRequiredNotDefined,
			ModifiedUserInteraction:    UserInteractionNotDefined,
			ModifiedScope:              ScopeNotDefined,
			ModifiedConfidentiality:    ConfidentialityImpactNotDefined,
			ModifiedIntegrity:          IntegrityImpactNotDefined,
			ModifiedAvailability:       AvailabilityImpactNotDefined,
		},
	}
}

// ShouldParse likes Parse but without error returning.
func ShouldParse(s string) Vector {
	var p, _ = Parse(s)
	return p
}

// Parse parses Vector from CVSS(V3) vector string.
func Parse(s string) (Vector, error) {
	const mandatorySize = 9
	s = strings.TrimSpace(s)
	var v = DefaultVector()
	var parts = strings.Split(s, "/")
	if len(parts) < mandatorySize {
		return Vector{}, fmt.Errorf("illegal CVSS(V3) vector: %s", s)
	}
	for i, part := range parts {
		var kv = strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return Vector{}, fmt.Errorf("incomplete CVSS(V3) vector: %s", s)
		}
		var mn = strings.TrimSpace(kv[0])
		if mn == "" {
			return Vector{}, fmt.Errorf("incomplete CVSS(V3) vector: %s", s)
		}
		var mv = strings.TrimSpace(kv[1])
		if mv == "" {
			return Vector{}, fmt.Errorf("incomplete CVSS(V3) vector: %s", s)
		}
		switch mn {
		// version
		case "CVSS":
			v.Version = Version(mv)
			if !v.Version.isDefined() {
				return Vector{}, fmt.Errorf("invalid version '%s' in CVSS(V3) vector: %s", mv, s)
			}
		// base metrics
		case "AV":
			v.AttackVector = AttackVector(mv)
			if !v.AttackVector.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		case "AC":
			v.AttackComplexity = AttackComplexity(mv)
			if !v.AttackComplexity.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		case "PR":
			v.PrivilegesRequired = PrivilegesRequired(mv)
			if !v.PrivilegesRequired.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		case "UI":
			v.UserInteraction = UserInteraction(mv)
			if !v.UserInteraction.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		case "S":
			v.Scope = Scope(mv)
			if !v.Scope.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		case "C":
			v.ConfidentialityImpact = ConfidentialityImpact(mv)
			if !v.ConfidentialityImpact.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		case "I":
			v.IntegrityImpact = IntegrityImpact(mv)
			if !v.IntegrityImpact.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		case "A":
			v.AvailabilityImpact = AvailabilityImpact(mv)
			if !v.AvailabilityImpact.isDefined() {
				return Vector{}, fmt.Errorf("undefined mandatory metric '%s' in CVSS(V3) vector: %s", mn, s)
			}
		default:
			if i < mandatorySize {
				return Vector{}, fmt.Errorf("'%s' is not mandatory metric in CVSS(V3) vector: %s", mn, s)
			}
			switch mn {
			default:
				return Vector{}, fmt.Errorf("unknown metric '%s' in CVSS(V3) vector: %s", mn, s)
			// temporal metrics
			case "E":
				v.ExploitCodeMaturity = ExploitCodeMaturity(mv)
			case "RL":
				v.RemediationLevel = RemediationLevel(mv)
			case "RC":
				v.ReportConfidence = ReportConfidence(mv)
			// environmental metrics
			case "CR":
				v.ConfidentialityRequirement = SecurityRequirement(mv)
			case "IR":
				v.IntegrityRequirement = SecurityRequirement(mv)
			case "AR":
				v.AvailabilityRequirement = SecurityRequirement(mv)
			case "MAV":
				v.ModifiedAttackVector = AttackVector(mv)
			case "MAC":
				v.ModifiedAttackComplexity = AttackComplexity(mv)
			case "MPR":
				v.ModifiedPrivilegesRequired = PrivilegesRequired(mv)
			case "MUI":
				v.ModifiedUserInteraction = UserInteraction(mv)
			case "MS":
				v.ModifiedScope = Scope(mv)
			case "MC":
				v.ModifiedConfidentiality = ConfidentialityImpact(mv)
			case "MI":
				v.ModifiedIntegrity = IntegrityImpact(mv)
			case "MA":
				v.ModifiedAvailability = AvailabilityImpact(mv)
			}
		}
	}
	return v, nil
}

// Vector holds the metrics vector of CVSS(V3).
type Vector struct {
	Version
	BasicMetrics
	TemporalMetrics
	EnvironmentalMetrics
}

// RawImpactScore return the raw impact score of this CVSS(V3) vector.
func (in Vector) RawImpactScore(modified bool) float64 {
	var c = in.getConfidentialityImpact()
	var i = in.getIntegrityImpact()
	var a = in.getAvailabilityImpact()
	if modified {
		var mc = in.getModifiedConfidentiality()
		if mc != 1 {
			c = mc
		}
		var mi = in.getModifiedIntegrity()
		if mi != 1 {
			i = mi
		}
		var ma = in.getModifiedAvailability()
		if ma != 1 {
			a = ma
		}
	}
	var b float64
	if modified {
		var cr = in.getConfidentialityRequirement()
		var ir = in.getIntegrityRequirement()
		var ar = in.getAvailabilityRequirement()
		b = math.Min(0.915, 1-(1-c*cr)*(1-i*ir)*(1-a*ar))
	} else {
		b = 1 - (1-c)*(1-i)*(1-a)
	}

	var s = in.Scope
	if modified && in.ModifiedScope.isDefined() {
		s = in.ModifiedScope
	}
	if s == ScopeUnchanged {
		return 6.42 * b
	}
	if modified && in.ModifiedScope.isDefined() && in.Version == Version31 {
		// ref to https://www.first.org/cvss/v3.1/user-guide#2-6-3-Change-to-ModifiedImpact-Sub-formula-in-Environmental-Metric.-Group.
		return 7.52*(b-0.029) - 3.25*math.Pow(b*0.9731-0.02, 13)
	}
	return 7.52*(b-0.029) - 3.25*math.Pow(b-0.02, 15)
}

// RawExploitabilityScore return the raw exploitability score of this CVSS(V3) vector.
func (in Vector) RawExploitabilityScore(modified bool) float64 {
	var av = in.getAttackVector()
	var ac = in.getAttackComplexity()
	var pr = in.getPrivilegesRequired()
	var ui = in.getUserInteraction()
	if modified {
		var mav = in.getModifiedAttackVector()
		if mav != 1 {
			av = mav
		}
		var mac = in.getModifiedAttackComplexity()
		if mac != 1 {
			ac = mac
		}
		var mpr = in.getModifiedPrivilegesRequired()
		if mpr != 1 {
			pr = mpr
		}
		var mui = in.getModifiedUserInteraction()
		if mui != 1 {
			ui = mui
		}
	}
	return 8.22 * av * ac * pr * ui
}

// ImpactScore returns the impact score of this CVSS(V3) vector.
func (in Vector) ImpactScore() float64 {
	return round(in.RawImpactScore(false))
}

// ExploitabilityScore returns the exploitability score of this CVSS(V3) vector.
func (in Vector) ExploitabilityScore() float64 {
	return round(in.RawExploitabilityScore(false))
}

// BaseScore returns the base score of this CVSS(V3) vector.
func (in Vector) BaseScore() float64 {
	var i = in.RawImpactScore(false)
	if i <= 0 {
		return 0.0
	}
	var e = in.RawExploitabilityScore(false)

	var c = 1.0
	var s = in.Scope
	if s == ScopeChanged {
		c = 1.08
	}
	return roundUp(math.Min(10, c*(i+e)), in.Version)
}

// BaseSeverity returns the base severity of this CVSS(V3) vector.
func (in Vector) BaseSeverity() string {
	return GetSeverityByScore(in.BaseScore())
}

// BaseScoreAndSeverity returns the base score and severity of this CVSS(V3) vector.
func (in Vector) BaseScoreAndSeverity() (score float64, severity string) {
	score = in.BaseScore()
	severity = GetSeverityByScore(score)
	return
}

// TemporalScore returns the temporal score of this CVSS(V3) vector.
func (in Vector) TemporalScore(baseScore ...float64) float64 {
	var bs float64
	if len(baseScore) == 0 {
		bs = in.BaseScore()
	} else {
		bs = baseScore[0]
	}
	var exp = in.getExploitCodeMaturity()
	var rl = in.getRemediationLevel()
	var rc = in.getReportConfidence()
	return roundUp(bs*exp*rl*rc, in.Version)
}

// TemporalSeverity returns the temporal severity of this CVSS(V3) vector.
func (in Vector) TemporalSeverity(baseScore ...float64) string {
	return GetSeverityByScore(in.TemporalScore(baseScore...))
}

// TemporalScoreAndSeverity returns the temporal score and severity of this CVSS(V3) vector.
func (in Vector) TemporalScoreAndSeverity(baseScore ...float64) (score float64, severity string) {
	score = in.TemporalScore(baseScore...)
	severity = GetSeverityByScore(score)
	return
}

// EnvironmentalScore returns the environmental score of this CVSS(V3) vector.
func (in Vector) EnvironmentalScore() float64 {
	var i = in.RawImpactScore(true)
	if i <= 0 {
		return 0.0
	}
	var e = in.RawExploitabilityScore(true)

	var exp = in.getExploitCodeMaturity()
	var rl = in.getRemediationLevel()
	var rc = in.getReportConfidence()

	var c = 1.0
	var s = in.Scope
	if in.ModifiedScope.isDefined() {
		s = in.ModifiedScope
	}
	if s == ScopeChanged {
		c = 1.08
	}
	return roundUp(roundUp(math.Min(10, c*(i+e)), in.Version)*exp*rl*rc, in.Version)
}

// EnvironmentalSeverity returns the environmental severity of this CVSS(V3) vector.
func (in Vector) EnvironmentalSeverity() string {
	return GetSeverityByScore(in.EnvironmentalScore())
}

// EnvironmentalScoreAndSeverity returns the environmental score and severity of this CVSS(V3) vector.
func (in Vector) EnvironmentalScoreAndSeverity() (score float64, severity string) {
	score = in.EnvironmentalScore()
	severity = GetSeverityByScore(score)
	return
}

// ScoreAndSeverity returns the score and severity of this CVSS(V3) vector, including
// - BaseScore and BaseSeverity
// - TemporalScore and TemporalSeverity
// - EnvironmentalScore and EnvironmentalSeverity
func (in Vector) ScoreAndSeverity() (bs float64, bsv string, ts float64, tsv string, es float64, esv string) {
	bs, bsv = in.BaseScoreAndSeverity()
	ts, tsv = in.TemporalScoreAndSeverity(bs)
	es, esv = in.EnvironmentalScoreAndSeverity()
	return
}

// GetVersion returns the cvss version of this CVSS(V3) vector.
func (in Vector) GetVersion() string {
	if in.Version.isDefined() {
		return string(in.Version)
	}
	return string(Version31)
}

// String returns the string format of this CVSS(V3) vector.
func (in Vector) String() string {
	var c = DefaultVector().Override(in)
	var sb strings.Builder

	// version
	sb.WriteString("CVSS:")
	sb.WriteString(string(c.Version))
	sb.WriteString("/")

	// base metrics
	sb.WriteString("AV:")
	sb.WriteString(string(c.AttackVector))
	sb.WriteString("/")
	sb.WriteString("AC:")
	sb.WriteString(string(c.AttackComplexity))
	sb.WriteString("/")
	sb.WriteString("PR:")
	sb.WriteString(string(c.PrivilegesRequired))
	sb.WriteString("/")
	sb.WriteString("UI:")
	sb.WriteString(string(c.UserInteraction))
	sb.WriteString("/")
	sb.WriteString("S:")
	sb.WriteString(string(c.Scope))
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
	if c.ExploitCodeMaturity != ExploitCodeMaturityNotDefined {
		sb.WriteString("/")
		sb.WriteString("E:")
		sb.WriteString(string(c.ExploitCodeMaturity))
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
	if c.ModifiedAttackVector != AttackVectorNotDefined {
		sb.WriteString("/")
		sb.WriteString("MAV:")
		sb.WriteString(string(c.ModifiedAttackVector))
	}
	if c.ModifiedAttackComplexity != AttackComplexityNotDefined {
		sb.WriteString("/")
		sb.WriteString("MAC:")
		sb.WriteString(string(c.ModifiedAttackComplexity))
	}
	if c.ModifiedPrivilegesRequired != PrivilegesRequiredNotDefined {
		sb.WriteString("/")
		sb.WriteString("MPR:")
		sb.WriteString(string(c.ModifiedPrivilegesRequired))
	}
	if c.ModifiedUserInteraction != UserInteractionNotDefined {
		sb.WriteString("/")
		sb.WriteString("MUI:")
		sb.WriteString(string(c.ModifiedUserInteraction))
	}
	if c.ModifiedScope != ScopeNotDefined {
		sb.WriteString("/")
		sb.WriteString("MS:")
		sb.WriteString(string(c.ModifiedScope))
	}
	if c.ModifiedConfidentiality != ConfidentialityImpactNotDefined {
		sb.WriteString("/")
		sb.WriteString("MC:")
		sb.WriteString(string(c.ModifiedConfidentiality))
	}
	if c.ModifiedIntegrity != IntegrityImpactNotDefined {
		sb.WriteString("/")
		sb.WriteString("MI:")
		sb.WriteString(string(c.ModifiedIntegrity))
	}
	if c.ModifiedAvailability != AvailabilityImpactNotDefined {
		sb.WriteString("/")
		sb.WriteString("MA:")
		sb.WriteString(string(c.ModifiedAvailability))
	}

	return sb.String()
}

// IsZero returns true if this CVSS(V3) vector is empty,
// DefaultVector is also an empty vector.
func (in Vector) IsZero() bool {
	return in == DefaultVector() || in == Vector{}
}

// ToLatest converts this CVSS(V3) vector to the latest version CVSS vector,
// this might loss precision, but try to keep in the same BaseSeverity or raise.
func (in Vector) ToLatest() compatible.Vector {
	if in.Version == Version31 {
		return in
	}
	var out = in
	out.Version = Version31
	return out
}

// Override merges the valued metrics of the given Vector.
func (in Vector) Override(v Vector) (out Vector) {
	out = in

	// version
	if v.Version != "" {
		out.Version = v.Version
	}

	// basic metrics
	var bm = v.BasicMetrics
	if bm.AttackVector != "" {
		out.AttackVector = bm.AttackVector
	}
	if bm.AttackComplexity != "" {
		out.AttackComplexity = bm.AttackComplexity
	}
	if bm.PrivilegesRequired != "" {
		out.PrivilegesRequired = bm.PrivilegesRequired
	}
	if bm.UserInteraction != "" {
		out.UserInteraction = bm.UserInteraction
	}
	if bm.Scope != "" {
		out.Scope = bm.Scope
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
	if tm.ExploitCodeMaturity != "" {
		out.ExploitCodeMaturity = tm.ExploitCodeMaturity
	}
	if tm.RemediationLevel != "" {
		out.RemediationLevel = tm.RemediationLevel
	}
	if tm.ReportConfidence != "" {
		out.ReportConfidence = tm.ReportConfidence
	}
	// environmental metrics
	var em = v.EnvironmentalMetrics
	if em.ConfidentialityRequirement != "" {
		out.ConfidentialityRequirement = em.ConfidentialityRequirement
	}
	if em.IntegrityRequirement != "" {
		out.IntegrityRequirement = em.IntegrityRequirement
	}
	if em.AvailabilityRequirement != "" {
		out.AvailabilityRequirement = em.AvailabilityRequirement
	}
	if em.ModifiedAttackVector != "" {
		out.ModifiedAttackVector = em.ModifiedAttackVector
	}
	if em.ModifiedAttackComplexity != "" {
		out.ModifiedAttackComplexity = em.ModifiedAttackComplexity
	}
	if em.ModifiedPrivilegesRequired != "" {
		out.ModifiedPrivilegesRequired = em.ModifiedPrivilegesRequired
	}
	if em.ModifiedUserInteraction != "" {
		out.ModifiedUserInteraction = em.ModifiedUserInteraction
	}
	if em.ModifiedScope != "" {
		out.ModifiedScope = em.ModifiedScope
	}
	if em.ModifiedConfidentiality != "" {
		out.ModifiedConfidentiality = em.ModifiedConfidentiality
	}
	if em.ModifiedIntegrity != "" {
		out.ModifiedIntegrity = em.ModifiedIntegrity
	}
	if em.ModifiedAvailability != "" {
		out.ModifiedAvailability = em.ModifiedAvailability
	}

	return
}

// Version of CVSS(V3) vector.
type Version string

// constants of Version.
const (
	Version30 Version = "3.0"
	Version31 Version = "3.1"
)

func (in Version) isDefined() bool {
	switch in {
	default:
		return false
	case Version30:
	case Version31:
	}
	return true
}

// types of basic metrics.
type (
	BasicMetrics struct {
		// Exploitability Metrics
		AttackVector
		AttackComplexity
		PrivilegesRequired
		UserInteraction
		// Scopes
		Scope
		// Impact Metrics
		ConfidentialityImpact
		IntegrityImpact
		AvailabilityImpact
	}

	AttackVector          string
	AttackComplexity      string
	PrivilegesRequired    string
	UserInteraction       string
	Scope                 string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
)

// constants of basic metrics.
const (
	AttackVectorNotDefined AttackVector = "X"
	AttackVectorPhysical   AttackVector = "P"
	AttackVectorLocal      AttackVector = "L"
	AttackVectorAdjacent   AttackVector = "A"
	AttackVectorNetwork    AttackVector = "N"

	AttackComplexityNotDefined AttackComplexity = "X"
	AttackComplexityHigh       AttackComplexity = "H"
	AttackComplexityLow        AttackComplexity = "L"

	PrivilegesRequiredNotDefined PrivilegesRequired = "X"
	PrivilegesRequiredHigh       PrivilegesRequired = "H"
	PrivilegesRequiredLow        PrivilegesRequired = "L"
	PrivilegesRequiredNone       PrivilegesRequired = "N"

	UserInteractionNotDefined UserInteraction = "X"
	UserInteractionRequired   UserInteraction = "R"
	UserInteractionNone       UserInteraction = "N"

	ScopeNotDefined Scope = "X"
	ScopeUnchanged  Scope = "U"
	ScopeChanged    Scope = "C"

	ConfidentialityImpactNotDefined ConfidentialityImpact = "X"
	ConfidentialityImpactNone       ConfidentialityImpact = "N"
	ConfidentialityImpactLow        ConfidentialityImpact = "L"
	ConfidentialityImpactHigh       ConfidentialityImpact = "H"

	IntegrityImpactNotDefined IntegrityImpact = "X"
	IntegrityImpactNone       IntegrityImpact = "N"
	IntegrityImpactLow        IntegrityImpact = "L"
	IntegrityImpactHigh       IntegrityImpact = "H"

	AvailabilityImpactNotDefined AvailabilityImpact = "X"
	AvailabilityImpactNone       AvailabilityImpact = "N"
	AvailabilityImpactLow        AvailabilityImpact = "L"
	AvailabilityImpactHigh       AvailabilityImpact = "H"
)

func (in AttackVector) isDefined() bool {
	switch in {
	default:
		return false
	case AttackVectorPhysical:
	case AttackVectorLocal:
	case AttackVectorAdjacent:
	case AttackVectorNetwork:
	}
	return true
}

func (in AttackComplexity) isDefined() bool {
	switch in {
	default:
		return false
	case AttackComplexityHigh:
	case AttackComplexityLow:
	}
	return true
}

func (in PrivilegesRequired) isDefined() bool {
	switch in {
	default:
		return false
	case PrivilegesRequiredHigh:
	case PrivilegesRequiredLow:
	case PrivilegesRequiredNone:
	}
	return true
}

func (in UserInteraction) isDefined() bool {
	switch in {
	default:
		return false
	case UserInteractionRequired:
	case UserInteractionNone:
	}
	return true
}

func (in Scope) isDefined() bool {
	switch in {
	default:
		return false
	case ScopeUnchanged:
	case ScopeChanged:
	}
	return true
}

func (in ConfidentialityImpact) isDefined() bool {
	switch in {
	default:
		return false
	case ConfidentialityImpactNone:
	case ConfidentialityImpactLow:
	case ConfidentialityImpactHigh:
	}
	return true
}

func (in IntegrityImpact) isDefined() bool {
	switch in {
	default:
		return false
	case IntegrityImpactNone:
	case IntegrityImpactLow:
	case IntegrityImpactHigh:
	}
	return true
}

func (in AvailabilityImpact) isDefined() bool {
	switch in {
	default:
		return false
	case AvailabilityImpactNone:
	case AvailabilityImpactLow:
	case AvailabilityImpactHigh:
	}
	return true
}

func (in BasicMetrics) getAttackVector() float64 {
	switch in.AttackVector {
	default:
		fallthrough
	case AttackVectorPhysical:
		return 0.2
	case AttackVectorLocal:
		return 0.55
	case AttackVectorAdjacent:
		return 0.62
	case AttackVectorNetwork:
		return 0.85
	}
}

func (in BasicMetrics) getAttackComplexity() float64 {
	switch in.AttackComplexity {
	default:
		fallthrough
	case AttackComplexityHigh:
		return 0.44
	case AttackComplexityLow:
		return 0.77
	}
}

func (in BasicMetrics) getPrivilegesRequired() float64 {
	switch in.PrivilegesRequired {
	default:
		fallthrough
	case PrivilegesRequiredHigh:
		if in.Scope == ScopeChanged {
			return 0.5
		}
		return 0.27
	case PrivilegesRequiredLow:
		if in.Scope == ScopeChanged {
			return 0.68
		}
		return 0.62
	case PrivilegesRequiredNone:
		return 0.85
	}
}

func (in BasicMetrics) getUserInteraction() float64 {
	switch in.UserInteraction {
	default:
		fallthrough
	case UserInteractionRequired:
		return 0.62
	case UserInteractionNone:
		return 0.85
	}
}

func (in BasicMetrics) getConfidentialityImpact() float64 {
	switch in.ConfidentialityImpact {
	default:
		fallthrough
	case ConfidentialityImpactNone:
		return 0
	case ConfidentialityImpactLow:
		return 0.22
	case ConfidentialityImpactHigh:
		return 0.56
	}
}

func (in BasicMetrics) getIntegrityImpact() float64 {
	switch in.IntegrityImpact {
	default:
		fallthrough
	case IntegrityImpactNone:
		return 0
	case IntegrityImpactLow:
		return 0.22
	case IntegrityImpactHigh:
		return 0.56
	}
}

func (in BasicMetrics) getAvailabilityImpact() float64 {
	switch in.AvailabilityImpact {
	default:
		fallthrough
	case AvailabilityImpactNone:
		return 0
	case AvailabilityImpactLow:
		return 0.22
	case AvailabilityImpactHigh:
		return 0.56
	}
}

// types of temporal metrics.
type (
	TemporalMetrics struct {
		ExploitCodeMaturity
		RemediationLevel
		ReportConfidence
	}

	ExploitCodeMaturity string
	RemediationLevel    string
	ReportConfidence    string
)

// constants of temporal metrics.
const (
	ExploitCodeMaturityNotDefined     ExploitCodeMaturity = "X"
	ExploitCodeMaturityUnproven       ExploitCodeMaturity = "U"
	ExploitCodeMaturityProofOfConcept ExploitCodeMaturity = "P"
	ExploitCodeMaturityFunctional     ExploitCodeMaturity = "F"
	ExploitCodeMaturityHigh           ExploitCodeMaturity = "H"

	RemediationLevelNotDefined   RemediationLevel = "X"
	RemediationLevelOfficialFix  RemediationLevel = "O"
	RemediationLevelTemporaryFix RemediationLevel = "T"
	RemediationLevelWorkaround   RemediationLevel = "W"
	RemediationLevelUnavailable  RemediationLevel = "U"

	ReportConfidenceNotDefined ReportConfidence = "X"
	ReportConfidenceUnknown    ReportConfidence = "U"
	ReportConfidenceReasonable ReportConfidence = "R"
	ReportConfidenceConfirmed  ReportConfidence = "C"
)

func (in TemporalMetrics) getExploitCodeMaturity() float64 {
	switch in.ExploitCodeMaturity {
	default:
		fallthrough
	case ExploitCodeMaturityNotDefined:
		return 1
	case ExploitCodeMaturityUnproven:
		return 0.91
	case ExploitCodeMaturityProofOfConcept:
		return 0.94
	case ExploitCodeMaturityFunctional:
		return 0.97
	case ExploitCodeMaturityHigh:
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
		return 0.95
	case RemediationLevelTemporaryFix:
		return 0.96
	case RemediationLevelWorkaround:
		return 0.97
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
	case ReportConfidenceUnknown:
		return 0.92
	case ReportConfidenceReasonable:
		return 0.96
	case ReportConfidenceConfirmed:
		return 1
	}
}

// types of environmental metrics.
type (
	EnvironmentalMetrics struct {
		// Security Requirements
		ConfidentialityRequirement SecurityRequirement
		IntegrityRequirement       SecurityRequirement
		AvailabilityRequirement    SecurityRequirement
		// Modified Base Metrics
		ModifiedAttackVector       AttackVector
		ModifiedAttackComplexity   AttackComplexity
		ModifiedPrivilegesRequired PrivilegesRequired
		ModifiedUserInteraction    UserInteraction
		ModifiedScope              Scope
		ModifiedConfidentiality    ConfidentialityImpact
		ModifiedIntegrity          IntegrityImpact
		ModifiedAvailability       AvailabilityImpact
	}

	SecurityRequirement string
)

// constants of environmental metrics.
const (
	SecurityRequirementNotDefined SecurityRequirement = "X"
	SecurityRequirementLow        SecurityRequirement = "L"
	SecurityRequirementMedium     SecurityRequirement = "M"
	SecurityRequirementHigh       SecurityRequirement = "H"
)

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
		return 1.5
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
		return 1.5
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
		return 1.5
	}
}

func (in EnvironmentalMetrics) getModifiedAttackVector() float64 {
	switch in.ModifiedAttackVector {
	default:
		fallthrough
	case AttackVectorNotDefined:
		return 1
	case AttackVectorPhysical:
		return 0.2
	case AttackVectorLocal:
		return 0.55
	case AttackVectorAdjacent:
		return 0.62
	case AttackVectorNetwork:
		return 0.85
	}
}

func (in EnvironmentalMetrics) getModifiedAttackComplexity() float64 {
	switch in.ModifiedAttackComplexity {
	default:
		fallthrough
	case AttackComplexityNotDefined:
		return 1
	case AttackComplexityHigh:
		return 0.44
	case AttackComplexityLow:
		return 0.77
	}
}

func (in EnvironmentalMetrics) getModifiedPrivilegesRequired() float64 {
	switch in.ModifiedPrivilegesRequired {
	default:
		fallthrough
	case PrivilegesRequiredNotDefined:
		return 1
	case PrivilegesRequiredHigh:
		if in.ModifiedScope == ScopeChanged {
			return 0.5
		}
		return 0.27
	case PrivilegesRequiredLow:
		if in.ModifiedScope == ScopeChanged {
			return 0.68
		}
		return 0.62
	case PrivilegesRequiredNone:
		return 0.85
	}
}

func (in EnvironmentalMetrics) getModifiedUserInteraction() float64 {
	switch in.ModifiedUserInteraction {
	default:
		fallthrough
	case UserInteractionNotDefined:
		return 1
	case UserInteractionRequired:
		return 0.62
	case UserInteractionNone:
		return 0.85
	}
}

func (in EnvironmentalMetrics) getModifiedConfidentiality() float64 {
	switch in.ModifiedConfidentiality {
	default:
		fallthrough
	case ConfidentialityImpactNotDefined:
		return 1
	case ConfidentialityImpactNone:
		return 0
	case ConfidentialityImpactLow:
		return 0.22
	case ConfidentialityImpactHigh:
		return 0.56
	}
}

func (in EnvironmentalMetrics) getModifiedIntegrity() float64 {
	switch in.ModifiedIntegrity {
	default:
		fallthrough
	case IntegrityImpactNotDefined:
		return 1
	case IntegrityImpactNone:
		return 0
	case IntegrityImpactLow:
		return 0.22
	case IntegrityImpactHigh:
		return 0.56
	}
}

func (in EnvironmentalMetrics) getModifiedAvailability() float64 {
	switch in.ModifiedAvailability {
	default:
		fallthrough
	case AvailabilityImpactNotDefined:
		return 1
	case AvailabilityImpactNone:
		return 0
	case AvailabilityImpactLow:
		return 0.22
	case AvailabilityImpactHigh:
		return 0.56
	}
}

func roundUp(f float64, v Version) float64 {
	if f <= 0 {
		return 0.0
	}
	if v == Version31 {
		// ref to https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding.
		var i = int(math.Round(f * 100000))
		if i%10000 == 0 {
			return float64(i) / 100000
		}
		return (math.Floor(float64(i)/10000) + 1) / 10
	}
	return math.Ceil(f*10) / 10
}

func round(f float64) float64 {
	if f <= 0 {
		return 0.0
	}
	return math.Round(f*10) / 10
}

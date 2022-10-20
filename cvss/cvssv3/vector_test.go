package cvssv3

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"
)

func TestParse(t *testing.T) {
	type output struct {
		r   Vector
		err error
	}
	var testCases = []struct {
		given    string
		expected output
	}{
		{
			given: DefaultVector().String(),
			expected: output{
				r: DefaultVector(),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			expected: output{
				r: Vector{
					Version: Version31,
					BasicMetrics: BasicMetrics{
						AttackVector:          AttackVectorNetwork,
						AttackComplexity:      AttackComplexityLow,
						PrivilegesRequired:    PrivilegesRequiredNone,
						UserInteraction:       UserInteractionNone,
						Scope:                 ScopeUnchanged,
						ConfidentialityImpact: ConfidentialityImpactNone,
						IntegrityImpact:       IntegrityImpactNone,
						AvailabilityImpact:    AvailabilityImpactHigh,
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
				},
			},
		},
		{
			given: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:W/RC:R",
			expected: output{
				r: Vector{
					Version: Version30,
					BasicMetrics: BasicMetrics{
						AttackVector:          AttackVectorNetwork,
						AttackComplexity:      AttackComplexityLow,
						PrivilegesRequired:    PrivilegesRequiredNone,
						UserInteraction:       UserInteractionNone,
						Scope:                 ScopeUnchanged,
						ConfidentialityImpact: ConfidentialityImpactNone,
						IntegrityImpact:       IntegrityImpactNone,
						AvailabilityImpact:    AvailabilityImpactHigh,
					},
					TemporalMetrics: TemporalMetrics{
						ExploitCodeMaturity: ExploitCodeMaturityUnproven,
						RemediationLevel:    RemediationLevelWorkaround,
						ReportConfidence:    ReportConfidenceReasonable,
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
				},
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:W/RC:R/CR:L/MUI:R",
			expected: output{
				r: Vector{
					Version: Version31,
					BasicMetrics: BasicMetrics{
						AttackVector:          AttackVectorNetwork,
						AttackComplexity:      AttackComplexityLow,
						PrivilegesRequired:    PrivilegesRequiredNone,
						UserInteraction:       UserInteractionNone,
						Scope:                 ScopeUnchanged,
						ConfidentialityImpact: ConfidentialityImpactNone,
						IntegrityImpact:       IntegrityImpactNone,
						AvailabilityImpact:    AvailabilityImpactHigh,
					},
					TemporalMetrics: TemporalMetrics{
						ExploitCodeMaturity: ExploitCodeMaturityUnproven,
						RemediationLevel:    RemediationLevelWorkaround,
						ReportConfidence:    ReportConfidenceReasonable,
					},
					EnvironmentalMetrics: EnvironmentalMetrics{
						ConfidentialityRequirement: SecurityRequirementLow,
						IntegrityRequirement:       SecurityRequirementNotDefined,
						AvailabilityRequirement:    SecurityRequirementNotDefined,
						ModifiedAttackVector:       AttackVectorNotDefined,
						ModifiedAttackComplexity:   AttackComplexityNotDefined,
						ModifiedPrivilegesRequired: PrivilegesRequiredNotDefined,
						ModifiedUserInteraction:    UserInteractionRequired,
						ModifiedScope:              ScopeNotDefined,
						ModifiedConfidentiality:    ConfidentialityImpactNotDefined,
						ModifiedIntegrity:          IntegrityImpactNotDefined,
						ModifiedAvailability:       AvailabilityImpactNotDefined,
					},
				},
			},
		},
		{
			given: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			expected: output{
				err: errors.New("illegal CVSS(V3) vector: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A",
			expected: output{
				err: errors.New("incomplete CVSS(V3) vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A"),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:/A:H",
			expected: output{
				err: errors.New("incomplete CVSS(V3) vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:/A:H"),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/:/A:H",
			expected: output{
				err: errors.New("incomplete CVSS(V3) vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/:/A:H"),
			},
		},
		{
			given: "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			expected: output{
				err: errors.New("invalid version '3.2' in CVSS(V3) vector: CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:X",
			expected: output{
				err: errors.New("undefined mandatory metric 'A' in CVSS(V3) vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:X"),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/E:X",
			expected: output{
				err: errors.New("'E' is not mandatory metric in CVSS(V3) vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/E:X"),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/D:X",
			expected: output{
				err: errors.New("unknown metric 'D' in CVSS(V3) vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/D:X"),
			},
		},
	}
	for _, c := range testCases {
		var actual output
		actual.r, actual.err = Parse(c.given)
		if c.expected.err != nil {
			if fmt.Sprint(actual.err) != fmt.Sprint(c.expected.err) {
				t.Errorf("Parse(%s) == %v, but got %v",
					c.given, c.expected.err, actual.err)
			}
		} else {
			if c.expected.r != actual.r {
				t.Errorf("Parse(%s) == %v, but got %v",
					c.given, c.expected.r, actual.r)
			}
		}
	}
}

func TestScore(t *testing.T) {
	type output struct {
		impactScore           float64
		exploitabilityScore   float64
		baseScore             float64
		baseSeverity          string
		temporalScore         float64
		temporalSeverity      string
		environmentalScore    float64
		environmentalSeverity string
	}
	var testCases = []struct {
		given    string
		expected output
	}{
		// example, https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N.
		{
			given: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
			expected: output{
				impactScore:           1.4,
				exploitabilityScore:   2.2,
				baseScore:             3.7,
				baseSeverity:          SeverityLow,
				temporalScore:         3.7,
				temporalSeverity:      SeverityLow,
				environmentalScore:    3.7,
				environmentalSeverity: SeverityLow,
			},
		},
		// example, https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H.
		{
			given: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			expected: output{
				impactScore:           3.6,
				exploitabilityScore:   3.9,
				baseScore:             7.5,
				baseSeverity:          SeverityHigh,
				temporalScore:         7.5,
				temporalSeverity:      SeverityHigh,
				environmentalScore:    7.5,
				environmentalSeverity: SeverityHigh,
			},
		},
		// example, https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.
		{
			given: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected: output{
				impactScore:           5.9,
				exploitabilityScore:   3.9,
				baseScore:             9.8,
				baseSeverity:          SeverityCritical,
				temporalScore:         9.8,
				temporalSeverity:      SeverityCritical,
				environmentalScore:    9.8,
				environmentalSeverity: SeverityCritical,
			},
		},
		// conversion example, https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N.
		{
			given: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
			expected: output{
				impactScore:           3.6,
				exploitabilityScore:   2.2,
				baseScore:             5.9,
				baseSeverity:          SeverityMedium,
				temporalScore:         5.9,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    5.9,
				environmentalSeverity: SeverityMedium,
			},
		},
		// conversion example, temporal downgrade, https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C.
		{
			given: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C",
			expected: output{
				impactScore:           3.6,
				exploitabilityScore:   2.2,
				baseScore:             5.9,
				baseSeverity:          SeverityMedium,
				temporalScore:         5.6, // < 5.9
				temporalSeverity:      SeverityMedium,
				environmentalScore:    5.6,
				environmentalSeverity: SeverityMedium,
			},
		},
		// conversion example, environmental upgrade, https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H.
		{
			given: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
			expected: output{
				impactScore:           3.6,
				exploitabilityScore:   2.2,
				baseScore:             5.9,
				baseSeverity:          SeverityMedium,
				temporalScore:         5.6,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    9.5, // > 5.6, become CRITICAL severity
				environmentalSeverity: SeverityCritical,
			},
		},
		// example, https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N.
		{
			given: DefaultVector().String(),
			expected: output{
				impactScore:           0,
				exploitabilityScore:   0.1,
				baseScore:             0,
				baseSeverity:          SeverityNone,
				temporalScore:         0,
				temporalSeverity:      SeverityNone,
				environmentalScore:    0,
				environmentalSeverity: SeverityNone,
			},
		},
		// example, https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H.
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			expected: output{
				impactScore:           5.9,
				exploitabilityScore:   3.9,
				baseScore:             9.8,
				baseSeverity:          SeverityCritical,
				temporalScore:         9.8,
				temporalSeverity:      SeverityCritical,
				environmentalScore:    9.8,
				environmentalSeverity: SeverityCritical,
			},
		},
		// conversion example, https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N.
		{
			given: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
			expected: output{
				impactScore:           3.6,
				exploitabilityScore:   2.2,
				baseScore:             5.9,
				baseSeverity:          SeverityMedium,
				temporalScore:         5.9,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    5.9,
				environmentalSeverity: SeverityMedium,
			},
		},
		// conversion example, temporal downgrade, https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C.
		{
			given: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C",
			expected: output{
				impactScore:           3.6,
				exploitabilityScore:   2.2,
				baseScore:             5.9,
				baseSeverity:          SeverityMedium,
				temporalScore:         5.6, // < 5.9
				temporalSeverity:      SeverityMedium,
				environmentalScore:    5.6,
				environmentalSeverity: SeverityMedium,
			},
		},
		// conversion example, environmental upgrade, https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H.
		{
			given: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:W/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
			expected: output{
				impactScore:           3.6,
				exploitabilityScore:   2.2,
				baseScore:             5.9,
				baseSeverity:          SeverityMedium,
				temporalScore:         5.6,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    9.5, // > 5.6, become CRITICAL severity
				environmentalSeverity: SeverityCritical,
			},
		},
	}
	for _, c := range testCases {
		var actual output
		var v = ShouldParse(c.given)
		actual.impactScore = v.ImpactScore()
		actual.exploitabilityScore = v.ExploitabilityScore()
		actual.baseScore, actual.baseSeverity, actual.temporalScore, actual.temporalSeverity, actual.environmentalScore, actual.environmentalSeverity = v.ScoreAndSeverity()
		if actual != c.expected {
			t.Errorf("socres of %s == %#v, but got %#v", c.given, c.expected, actual)
		}
	}
}

func TestVector_String(t *testing.T) {
	var testCases = []struct {
		given    Vector
		expected string
	}{
		{
			given:    DefaultVector(),
			expected: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
		},
		{
			given: Vector{
				BasicMetrics: BasicMetrics{
					AttackVector:       AttackVectorNetwork,
					AvailabilityImpact: AvailabilityImpactHigh,
				},
				EnvironmentalMetrics: EnvironmentalMetrics{
					ModifiedConfidentiality: ConfidentialityImpactLow,
				},
			},
			expected: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/MC:L",
		},
	}
	for i, c := range testCases {
		var actual = c.given.String()
		if actual != c.expected {
			t.Errorf("#%d expected %s, but got %s", i+1, c.expected, actual)
		}
	}
}

func TestVector_ToLatest(t *testing.T) {
	var testCases = []struct {
		given    string
		expected string
	}{
		{
			given:    "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/MC:L",
			expected: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/MC:L",
		},
		{
			given:    "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/MC:L",
			expected: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H/MC:L",
		},
	}
	for i, c := range testCases {
		var actual = ShouldParse(c.given).ToLatest()
		if actual.String() != c.expected {
			t.Errorf("#%d expected %s, but got %s", i+1, c.expected, actual)
		}
	}
}

func TestVector_Override(t *testing.T) {
	type input struct {
		r Vector
		v Vector
	}
	var testCases = []struct {
		given    input
		expected Vector
	}{
		{
			given: input{
				r: DefaultVector(),
				v: Vector{
					Version: Version30,
					BasicMetrics: BasicMetrics{
						AttackVector:       AttackVectorNetwork,
						AvailabilityImpact: AvailabilityImpactHigh,
					},
				},
			},
			expected: Vector{
				Version: Version30,
				BasicMetrics: BasicMetrics{
					AttackVector:          AttackVectorNetwork,
					AttackComplexity:      AttackComplexityHigh,
					PrivilegesRequired:    PrivilegesRequiredHigh,
					UserInteraction:       UserInteractionRequired,
					Scope:                 ScopeUnchanged,
					ConfidentialityImpact: ConfidentialityImpactNone,
					IntegrityImpact:       IntegrityImpactNone,
					AvailabilityImpact:    AvailabilityImpactHigh,
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
			},
		},
		{
			given: input{
				r: DefaultVector(),
				v: Vector{
					TemporalMetrics: TemporalMetrics{
						ExploitCodeMaturity: ExploitCodeMaturityFunctional,
					},
				},
			},
			expected: Vector{
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
					ExploitCodeMaturity: ExploitCodeMaturityFunctional,
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
			},
		},
		{
			given: input{
				r: DefaultVector(),
				v: Vector{
					EnvironmentalMetrics: EnvironmentalMetrics{
						ModifiedAvailability: AvailabilityImpactHigh,
					},
				},
			},
			expected: Vector{
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
					ModifiedAvailability:       AvailabilityImpactHigh,
				},
			},
		},
	}
	for i, c := range testCases {
		var actual = c.given.r.Override(c.given.v)
		if actual != c.expected {
			t.Errorf("#%d error", i+1)
		}
	}
}

func TestUpgradeV31(t *testing.T) {
	type result struct {
		impactScore           float64
		exploitabilityScore   float64
		baseScore             float64
		baseSeverity          string
		temporalScore         float64
		temporalSeverity      string
		environmentalScore    float64
		environmentalSeverity string
	}
	type output struct {
		v30r result
		v30  result
		v31  result
	}
	type input struct {
		v30r string
		v30  string
		v31  string
	}

	var testCases = []struct {
		given    input
		expected output
	}{
		{
			// roundup function redefinition, https://www.first.org/cvss/v3.1/user-guide#2-6-2-Roundup-Function-Redefinition.
			given: input{
				v30: "CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U",
				v31: "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U",
			},
			expected: output{
				v30: result{
					impactScore:           4.7,
					exploitabilityScore:   0.3,
					baseScore:             5,
					baseSeverity:          SeverityMedium,
					temporalScore:         4.7,
					temporalSeverity:      SeverityMedium,
					environmentalScore:    4.7,
					environmentalSeverity: SeverityMedium,
				},
				v31: result{
					impactScore:           4.7,
					exploitabilityScore:   0.3,
					baseScore:             5,
					baseSeverity:          SeverityMedium,
					temporalScore:         4.6,
					temporalSeverity:      SeverityMedium,
					environmentalScore:    4.6,
					environmentalSeverity: SeverityMedium,
				},
			},
		},
		{
			// modified impact sub-formula change, https://www.first.org/cvss/v3.1/user-guide#2-6-3-Change-to-ModifiedImpact-Sub-formula-in-Environmental-Metric.-Group.
			given: input{
				v30r: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H",
				v30:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
				v31:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			expected: output{
				v30r: result{
					impactScore:           6,
					exploitabilityScore:   3.9,
					baseScore:             10,
					baseSeverity:          SeverityCritical,
					temporalScore:         8.1,
					temporalSeverity:      SeverityHigh,
					environmentalScore:    5.6,
					environmentalSeverity: SeverityMedium,
				},
				v30: result{
					impactScore:           6,
					exploitabilityScore:   3.9,
					baseScore:             10,
					baseSeverity:          SeverityCritical,
					temporalScore:         8.1,
					temporalSeverity:      SeverityHigh,
					environmentalScore:    5.5, // high modified impact but got lower score
					environmentalSeverity: SeverityMedium,
				},
				v31: result{
					impactScore:           6,
					exploitabilityScore:   3.9,
					baseScore:             10,
					baseSeverity:          SeverityCritical,
					temporalScore:         8.1,
					temporalSeverity:      SeverityHigh,
					environmentalScore:    5.6, // nothing change
					environmentalSeverity: SeverityMedium,
				},
			},
		},
	}
	for _, c := range testCases {
		var actual output

		if c.given.v30r != "" {
			var v30r = ShouldParse(c.given.v30r)
			actual.v30r.impactScore = v30r.ImpactScore()
			actual.v30r.exploitabilityScore = v30r.ExploitabilityScore()
			actual.v30r.baseScore = v30r.BaseScore()
			actual.v30r.baseSeverity = v30r.BaseSeverity()
			actual.v30r.temporalScore = v30r.TemporalScore()
			actual.v30r.temporalSeverity = v30r.TemporalSeverity()
			actual.v30r.environmentalScore = v30r.EnvironmentalScore()
			actual.v30r.environmentalSeverity = v30r.EnvironmentalSeverity()
		}

		var v30 = ShouldParse(c.given.v30)
		actual.v30.impactScore = v30.ImpactScore()
		actual.v30.exploitabilityScore = v30.ExploitabilityScore()
		actual.v30.baseScore = v30.BaseScore()
		actual.v30.baseSeverity = v30.BaseSeverity()
		actual.v30.temporalScore = v30.TemporalScore()
		actual.v30.temporalSeverity = v30.TemporalSeverity()
		actual.v30.environmentalScore = v30.EnvironmentalScore()
		actual.v30.environmentalSeverity = v30.EnvironmentalSeverity()

		var v31 = ShouldParse(c.given.v31)
		actual.v31.impactScore = v31.ImpactScore()
		actual.v31.exploitabilityScore = v31.ExploitabilityScore()
		actual.v31.baseScore = v31.BaseScore()
		actual.v31.baseSeverity = v31.BaseSeverity()
		actual.v31.temporalScore = v31.TemporalScore()
		actual.v31.temporalSeverity = v31.TemporalSeverity()
		actual.v31.environmentalScore = v31.EnvironmentalScore()
		actual.v31.environmentalSeverity = v31.EnvironmentalSeverity()

		if actual != c.expected {
			t.Errorf("socres of %s == %#v, but got %#v", c.given, c.expected, actual)
		}
	}
}

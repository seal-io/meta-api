package cvss

import (
	"fmt"
	"testing"

	"github.com/seal-io/meta-api/cvss/compatible"
	"github.com/seal-io/meta-api/cvss/cvssv2"
	"github.com/seal-io/meta-api/cvss/cvssv3"
)

func TestParse(t *testing.T) {
	type output struct {
		r   compatible.Vector
		err error
	}
	var testCases = []struct {
		given    string
		expected output
	}{
		{
			given: cvssv2.DefaultVector().String(),
			expected: output{
				r: cvssv2.DefaultVector(),
			},
		},
		{
			given: "AV:L/AC:L/Au:N/C:N/I:N/A:C/E:H/RL:TF/RC:UR/CDP:LM/TD:H/CR:L/IR:M/AR:H",
			expected: output{
				r: cvssv2.Vector{
					BasicMetrics: cvssv2.BasicMetrics{
						AccessVector:          cvssv2.AccessVectorLocal,
						AccessComplexity:      cvssv2.AccessComplexityLow,
						Authentication:        cvssv2.AuthenticationNone,
						ConfidentialityImpact: cvssv2.ConfidentialityImpactNone,
						IntegrityImpact:       cvssv2.IntegrityImpactNone,
						AvailabilityImpact:    cvssv2.AvailabilityImpactComplete,
					},
					TemporalMetrics: cvssv2.TemporalMetrics{
						Exploitability:   cvssv2.ExploitabilityHigh,
						RemediationLevel: cvssv2.RemediationLevelTemporaryFix,
						ReportConfidence: cvssv2.ReportConfidenceUncorroborated,
					},
					EnvironmentalMetrics: cvssv2.EnvironmentalMetrics{
						CollateralDamagePotential:  cvssv2.CollateralDamagePotentialLowMedium,
						TargetDistribution:         cvssv2.TargetDistributionHigh,
						ConfidentialityRequirement: cvssv2.SecurityRequirementLow,
						IntegrityRequirement:       cvssv2.SecurityRequirementMedium,
						AvailabilityRequirement:    cvssv2.SecurityRequirementHigh,
					},
				},
			},
		},
		{
			given: cvssv3.DefaultVector().String(),
			expected: output{
				r: cvssv3.DefaultVector(),
			},
		},
		{
			given: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:W/RC:R/CR:L/MUI:R",
			expected: output{
				r: cvssv3.Vector{
					Version: cvssv3.Version31,
					BasicMetrics: cvssv3.BasicMetrics{
						AttackVector:          cvssv3.AttackVectorNetwork,
						AttackComplexity:      cvssv3.AttackComplexityLow,
						PrivilegesRequired:    cvssv3.PrivilegesRequiredNone,
						UserInteraction:       cvssv3.UserInteractionNone,
						Scope:                 cvssv3.ScopeUnchanged,
						ConfidentialityImpact: cvssv3.ConfidentialityImpactNone,
						IntegrityImpact:       cvssv3.IntegrityImpactNone,
						AvailabilityImpact:    cvssv3.AvailabilityImpactHigh,
					},
					TemporalMetrics: cvssv3.TemporalMetrics{
						ExploitCodeMaturity: cvssv3.ExploitCodeMaturityUnproven,
						RemediationLevel:    cvssv3.RemediationLevelWorkaround,
						ReportConfidence:    cvssv3.ReportConfidenceReasonable,
					},
					EnvironmentalMetrics: cvssv3.EnvironmentalMetrics{
						ConfidentialityRequirement: cvssv3.SecurityRequirementLow,
						IntegrityRequirement:       cvssv3.SecurityRequirementNotDefined,
						AvailabilityRequirement:    cvssv3.SecurityRequirementNotDefined,
						ModifiedAttackVector:       cvssv3.AttackVectorNotDefined,
						ModifiedAttackComplexity:   cvssv3.AttackComplexityNotDefined,
						ModifiedPrivilegesRequired: cvssv3.PrivilegesRequiredNotDefined,
						ModifiedUserInteraction:    cvssv3.UserInteractionRequired,
						ModifiedScope:              cvssv3.ScopeNotDefined,
						ModifiedConfidentiality:    cvssv3.ConfidentialityImpactNotDefined,
						ModifiedIntegrity:          cvssv3.IntegrityImpactNotDefined,
						ModifiedAvailability:       cvssv3.AvailabilityImpactNotDefined,
					},
				},
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

package cvssv2

import (
	"errors"
	"fmt"
	"testing"

	"github.com/seal-io/meta-api/cvss/cvssv3"
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
			given: "AV:L/AC:M/Au:N/C:P/I:N/A:N",
			expected: output{
				r: Vector{
					BasicMetrics: BasicMetrics{
						AccessVector:          AccessVectorLocal,
						AccessComplexity:      AccessComplexityMedium,
						Authentication:        AuthenticationNone,
						ConfidentialityImpact: ConfidentialityImpactPartial,
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
				},
			},
		},
		{
			given: "AV:L/AC:M/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C",
			expected: output{
				r: Vector{
					BasicMetrics: BasicMetrics{
						AccessVector:          AccessVectorLocal,
						AccessComplexity:      AccessComplexityMedium,
						Authentication:        AuthenticationNone,
						ConfidentialityImpact: ConfidentialityImpactPartial,
						IntegrityImpact:       IntegrityImpactPartial,
						AvailabilityImpact:    AvailabilityImpactPartial,
					},
					TemporalMetrics: TemporalMetrics{
						Exploitability:   ExploitabilityUnproven,
						RemediationLevel: RemediationLevelOfficialFix,
						ReportConfidence: ReportConfidenceConfirmed,
					},
					EnvironmentalMetrics: EnvironmentalMetrics{
						CollateralDamagePotential:  CollateralDamagePotentialNotDefined,
						TargetDistribution:         TargetDistributionNotDefined,
						ConfidentialityRequirement: SecurityRequirementNotDefined,
						IntegrityRequirement:       SecurityRequirementNotDefined,
						AvailabilityRequirement:    SecurityRequirementNotDefined,
					},
				},
			},
		},
		{
			given: "AV:L/AC:L/Au:N/C:N/I:N/A:C/E:H/RL:TF/RC:UR/CDP:LM/TD:H/CR:L/IR:M/AR:H",
			expected: output{
				r: Vector{
					BasicMetrics: BasicMetrics{
						AccessVector:          AccessVectorLocal,
						AccessComplexity:      AccessComplexityLow,
						Authentication:        AuthenticationNone,
						ConfidentialityImpact: ConfidentialityImpactNone,
						IntegrityImpact:       IntegrityImpactNone,
						AvailabilityImpact:    AvailabilityImpactComplete,
					},
					TemporalMetrics: TemporalMetrics{
						Exploitability:   ExploitabilityHigh,
						RemediationLevel: RemediationLevelTemporaryFix,
						ReportConfidence: ReportConfidenceUncorroborated,
					},
					EnvironmentalMetrics: EnvironmentalMetrics{
						CollateralDamagePotential:  CollateralDamagePotentialLowMedium,
						TargetDistribution:         TargetDistributionHigh,
						ConfidentialityRequirement: SecurityRequirementLow,
						IntegrityRequirement:       SecurityRequirementMedium,
						AvailabilityRequirement:    SecurityRequirementHigh,
					},
				},
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C",
			expected: output{
				err: errors.New("illegal CVSS(V2) vector: AV:N/AC:L/Au:N/C:C/I:C"),
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/A",
			expected: output{
				err: errors.New("incomplete CVSS(V2) vector: AV:N/AC:L/Au:N/C:C/I:C/A"),
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/:C",
			expected: output{
				err: errors.New("incomplete CVSS(V2) vector: AV:N/AC:L/Au:N/C:C/I:C/:C"),
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/A:",
			expected: output{
				err: errors.New("incomplete CVSS(V2) vector: AV:N/AC:L/Au:N/C:C/I:C/A:"),
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/A:X",
			expected: output{
				err: errors.New("undefined mandatory metric 'A' in CVSS(V2) vector: AV:N/AC:L/Au:N/C:C/I:C/A:X"),
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/E:U",
			expected: output{
				err: errors.New("'E' is not mandatory metric in CVSS(V2) vector: AV:N/AC:L/Au:N/C:C/I:C/E:U"),
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/A:C/D:C",
			expected: output{
				err: errors.New("unknown metric 'D' in CVSS(V2) vector: AV:N/AC:L/Au:N/C:C/I:C/A:C/D:C"),
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
		{
			given: DefaultVector().String(),
			expected: output{
				impactScore:           0,
				exploitabilityScore:   1.2,
				baseScore:             0,
				baseSeverity:          SeverityLow,
				temporalScore:         0,
				temporalSeverity:      SeverityLow,
				environmentalScore:    0,
				environmentalSeverity: SeverityLow,
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
			expected: output{
				impactScore:           10,
				exploitabilityScore:   10,
				baseScore:             10,
				baseSeverity:          SeverityHigh,
				temporalScore:         10,
				temporalSeverity:      SeverityHigh,
				environmentalScore:    10,
				environmentalSeverity: SeverityHigh,
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:P/I:N/A:N",
			expected: output{
				impactScore:           2.9,
				exploitabilityScore:   10,
				baseScore:             5,
				baseSeverity:          SeverityMedium,
				temporalScore:         5,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    5,
				environmentalSeverity: SeverityMedium,
			},
		},
		{
			given: "AV:L/AC:M/Au:N/C:P/I:N/A:N",
			expected: output{
				impactScore:           2.9,
				exploitabilityScore:   3.4,
				baseScore:             1.9,
				baseSeverity:          SeverityLow,
				temporalScore:         1.9,
				temporalSeverity:      SeverityLow,
				environmentalScore:    1.9,
				environmentalSeverity: SeverityLow,
			},
		},
		// ref to https://www.first.org/cvss/v2/guide#3-3-1-CVE-2002-0392
		{
			given: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:H",
			expected: output{
				impactScore:           6.9,
				exploitabilityScore:   10,
				baseScore:             7.8,
				baseSeverity:          SeverityHigh,
				temporalScore:         6.4,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    0,
				environmentalSeverity: SeverityLow,
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H",
			expected: output{
				impactScore:           6.9,
				exploitabilityScore:   10,
				baseScore:             7.8,
				baseSeverity:          SeverityHigh,
				temporalScore:         6.4,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    9.1,
				environmentalSeverity: SeverityHigh,
			},
		},
		// ref to https://www.first.org/cvss/v2/guide#3-3-2-CVE-2003-0818
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:H",
			expected: output{
				impactScore:           10,
				exploitabilityScore:   10,
				baseScore:             10,
				baseSeverity:          SeverityHigh,
				temporalScore:         8.3,
				temporalSeverity:      SeverityHigh,
				environmentalScore:    0,
				environmentalSeverity: SeverityLow,
			},
		},
		{
			given: "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H",
			expected: output{
				impactScore:           10,
				exploitabilityScore:   10,
				baseScore:             10,
				baseSeverity:          SeverityHigh,
				temporalScore:         8.3,
				temporalSeverity:      SeverityHigh,
				environmentalScore:    9.1,
				environmentalSeverity: SeverityHigh,
			},
		},
		// ref to https://www.first.org/cvss/v2/guide#3-3-3-CVE-2003-0062
		{
			given: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:N/TD:N/CR:M/IR:M/AR:M",
			expected: output{
				impactScore:           10,
				exploitabilityScore:   1.9,
				baseScore:             6.2,
				baseSeverity:          SeverityMedium,
				temporalScore:         4.9,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    0,
				environmentalSeverity: SeverityLow,
			},
		},
		{
			given: "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M",
			expected: output{
				impactScore:           10,
				exploitabilityScore:   1.9,
				baseScore:             6.2,
				baseSeverity:          SeverityMedium,
				temporalScore:         4.9,
				temporalSeverity:      SeverityMedium,
				environmentalScore:    7.4,
				environmentalSeverity: SeverityHigh,
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
			expected: "AV:L/AC:H/Au:M/C:N/I:N/A:N",
		},
		{
			given: Vector{
				BasicMetrics: BasicMetrics{
					AccessVector:   AccessVectorNetwork,
					Authentication: AuthenticationNone,
				},
			},
			expected: "AV:N/AC:H/Au:N/C:N/I:N/A:N",
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
	type output struct {
		vectorString string
		baseSeverity string
	}
	var testCases = []struct {
		given    string
		expected output
	}{
		{ // CVE-1999-0199     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
			given: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			expected: output{
				vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				baseSeverity: cvssv3.SeverityCritical,
			},
		},
		{ // CVE-2002-20001    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
			given: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
			expected: output{
				vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				baseSeverity: cvssv3.SeverityHigh,
			},
		},
		{ // CVE-2006-4245     CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H    raise AC/UI/S, severity
			given: "AV:N/AC:M/Au:N/C:P/I:P/A:P",
			expected: output{
				vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
				baseSeverity: cvssv3.SeverityCritical,
			},
		},
		{ // CVE-2007-6745     CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
			given: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
			expected: output{
				vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				baseSeverity: cvssv3.SeverityCritical,
			},
		},
		{ // CVE-2010-1281     CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H    raise S, severity
			given: "AV:N/AC:M/Au:N/C:C/I:C/A:C",
			expected: output{
				vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
				baseSeverity: cvssv3.SeverityCritical,
			},
		},

		// same v2 AV:L/AC:L/Au:N/ prefix
		{ // CVE-2005-4890     CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
			given: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
			expected: output{
				vectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
				baseSeverity: cvssv3.SeverityHigh,
			},
		},
		{ // CVE-2006-3635     CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
			given: "AV:L/AC:L/Au:N/C:N/I:N/A:C",
			expected: output{
				vectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
				baseSeverity: cvssv3.SeverityMedium,
			},
		},
		{ // CVE-2009-5150     CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H    raise PR
			given: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
			expected: output{
				vectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
				baseSeverity: cvssv3.SeverityHigh,
			},
		},
		{ // CVE-2009-0783     CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L    raise PR/C/I/A
			given: "AV:L/AC:L/Au:N/C:P/I:P/A:P",
			expected: output{
				vectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
				baseSeverity: cvssv3.SeverityHigh,
			},
		},
		{ // CVE-2011-2343     CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N    loss AV/PR
			given: "AV:L/AC:L/Au:N/C:P/I:N/A:N",
			expected: output{
				vectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
				baseSeverity: cvssv3.SeverityLow,
			},
		},

		// same v2 input, but get detail changed in v3
		{ // CVE-2005-2350     CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N    loss C, raise I, severity
			given: "AV:N/AC:M/Au:N/C:N/I:P/A:N",
			expected: output{
				vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N",
				baseSeverity: cvssv3.SeverityHigh,
			},
		},
		{ // CVE-2007-5967     CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N    raise S, severity
			given: "AV:N/AC:M/Au:N/C:N/I:P/A:N",
			expected: output{
				vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N",
				baseSeverity: cvssv3.SeverityHigh,
			},
		},
	}
	for i, c := range testCases {
		var actual output
		var actualV = ShouldParse(c.given).ToLatest()
		actual.vectorString = actualV.String()
		actual.baseSeverity = actualV.BaseSeverity()
		if actual != c.expected {
			t.Errorf("#%d %s expected %v, but got %v", i+1, c.given, c.expected, actual)
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
					BasicMetrics: BasicMetrics{
						AccessVector:   AccessVectorNetwork,
						Authentication: AuthenticationNone,
					},
				},
			},
			expected: Vector{
				BasicMetrics: BasicMetrics{
					AccessVector:          AccessVectorNetwork,
					AccessComplexity:      AccessComplexityHigh,
					Authentication:        AuthenticationNone,
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
			},
		},
		{
			given: input{
				r: DefaultVector(),
				v: Vector{
					TemporalMetrics: TemporalMetrics{
						Exploitability: ExploitabilityUnproven,
					},
				},
			},
			expected: Vector{
				BasicMetrics: BasicMetrics{
					AccessVector:          AccessVectorLocal,
					AccessComplexity:      AccessComplexityHigh,
					Authentication:        AuthenticationMultiple,
					ConfidentialityImpact: ConfidentialityImpactNone,
					IntegrityImpact:       IntegrityImpactNone,
					AvailabilityImpact:    AvailabilityImpactNone,
				},
				TemporalMetrics: TemporalMetrics{
					Exploitability:   ExploitabilityUnproven,
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
			},
		},
		{
			given: input{
				r: DefaultVector(),
				v: Vector{
					EnvironmentalMetrics: EnvironmentalMetrics{
						TargetDistribution: TargetDistributionHigh,
					},
				},
			},
			expected: Vector{
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
					TargetDistribution:         TargetDistributionHigh,
					ConfidentialityRequirement: SecurityRequirementNotDefined,
					IntegrityRequirement:       SecurityRequirementNotDefined,
					AvailabilityRequirement:    SecurityRequirementNotDefined,
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

func TestGetScoreExampleBySeverity(t *testing.T) {
	var testCases = []struct {
		input  string
		output string
	}{
		{
			input:  SeverityHigh,
			output: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		},
		{
			input:  SeverityMedium,
			output: "AV:N/AC:L/Au:N/C:P/I:N/A:N",
		},
		{
			input:  SeverityLow,
			output: "AV:N/AC:M/Au:S/C:P/I:N/A:N",
		},
	}
	for _, c := range testCases {
		var aVs, aBs, aIs, aEs = GetScoreExampleBySeverity(c.input)
		var p = ShouldParse(c.output)
		var eVs = c.output
		var eBs = p.BaseScore()
		var eIs = p.ImpactScore()
		var eEs = p.ExploitabilityScore()
		if aVs != eVs || aBs != eBs || aIs != eIs || aEs != eEs {
			t.Errorf("GetScoreExampleBySeverity('%s') = %s, %.1f, %.1f, %.1f, but got %s, %.1f, %.1f, %.1f",
				c.input, eVs, eBs, eIs, eEs, aVs, aBs, aIs, aEs)
		}
	}
}

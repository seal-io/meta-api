package ssvc2

import (
	"fmt"
	"testing"
	"time"
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
			given: DefaultVector(StakeholderSupplier).String(),
			expected: output{
				r: DefaultVector(StakeholderSupplier),
			},
		},

		{
			given: "SSVCv2/E:P/A:N/V:D/U:L/T:T/P:I/R:I/2022-11-03T11:18:47Z/",
			expected: output{
				r: Vector{
					Stakeholder: StakeholderSupplier,
					Decisions: Decisions{
						Exploitation:        ExploitationPoC,
						Automatable:         AutomatableNo,
						ValueDensity:        ValueDensityDiffuse,
						_Utility:            "",
						TechnicalImpact:     TechnicalImpactTotal,
						_PublicSafetyImpact: PublicSafetyImpactSignificant,
					},
					Timestamp: func() time.Time {
						var v, _ = time.Parse(vectorTimestampFormat, "2022-11-03T11:18:47Z")
						return v
					}(),
				},
			},
		},
		{
			given: "SSVCv2/E:P/U:L/T:T/P:I/R:I/2022-11-03T11:18:47Z/",
			expected: output{
				r: Vector{
					Stakeholder: StakeholderSupplier,
					Decisions: Decisions{
						Exploitation:        ExploitationPoC,
						_Utility:            UtilityLaborious,
						TechnicalImpact:     TechnicalImpactTotal,
						_PublicSafetyImpact: PublicSafetyImpactSignificant,
					},
					Timestamp: func() time.Time {
						var v, _ = time.Parse(vectorTimestampFormat, "2022-11-03T11:18:47Z")
						return v
					}(),
				},
			},
		},

		{
			given: "SSVCv2/E:P/X:O/A:N/V:D/U:L/S:N/M:N/H:L/P:D/1667541906/",
			expected: output{
				r: Vector{
					Stakeholder: StakeholderDeployer,
					Decisions: Decisions{
						Exploitation:  ExploitationPoC,
						Exposure:      ExposureOpen,
						Automatable:   AutomatableNo,
						ValueDensity:  ValueDensityDiffuse,
						_Utility:      "",
						SafetyImpact:  SafetyImpactNone,
						MissionImpact: MissionImpactNone,
						_HumanImpact:  "",
					},
					Timestamp: time.Unix(1667541906, 0),
				},
			},
		},
		{
			given: "SSVCv2/E:P/X:O/U:L/H:L/P:D/1667541906/",
			expected: output{
				r: Vector{
					Stakeholder: StakeholderDeployer,
					Decisions: Decisions{
						Exploitation: ExploitationPoC,
						Exposure:     ExposureOpen,
						_Utility:     UtilityLaborious,
						_HumanImpact: HumanImpactLow,
					},
					Timestamp: time.Unix(1667541906, 0),
				},
			},
		},

		{
			// correct U with A/V
			given: "SSVCv2/E:P/A:Y/V:D/U:L/T:T/P:I/R:I/2022-11-03T11:18:47Z/",
			expected: output{
				r: Vector{
					Stakeholder: StakeholderSupplier,
					Decisions: Decisions{
						Exploitation:        ExploitationPoC,
						Automatable:         AutomatableYes,
						ValueDensity:        ValueDensityDiffuse,
						_Utility:            "", // string is laborious
						TechnicalImpact:     TechnicalImpactTotal,
						_PublicSafetyImpact: PublicSafetyImpactSignificant,
					},
					Timestamp: func() time.Time {
						var v, _ = time.Parse(vectorTimestampFormat, "2022-11-03T11:18:47Z")
						return v
					}(),
				},
			},
		},
		{
			// correct H with S/M
			given: "SSVCv2/E:P/X:O/A:N/V:D/U:L/S:H/M:M/H:L/P:D/1667541917/",
			expected: output{
				r: Vector{
					Stakeholder: StakeholderDeployer,
					Decisions: Decisions{
						Exploitation:  ExploitationPoC,
						Exposure:      ExposureOpen,
						Automatable:   AutomatableNo,
						ValueDensity:  ValueDensityDiffuse,
						_Utility:      "",
						SafetyImpact:  SafetyImpactHazardous,
						MissionImpact: MissionImpactMissionFailure,
						_HumanImpact:  "", // string is lower.
					},
					Timestamp: time.Unix(1667541917, 0),
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

func TestVector_String(t *testing.T) {
	var testCases = []struct {
		given    Vector
		expected string
	}{
		{
			given:    DefaultVector(StakeholderSupplier),
			expected: "SSVCv2/E:N/U:L/T:P/P:M/R:D/0001-01-01T00:00:00Z/",
		},
		{
			given: Vector{
				Stakeholder: StakeholderSupplier,
				Decisions: Decisions{
					Exploitation:    ExploitationActive,
					TechnicalImpact: TechnicalImpactPartial,
				}.WithUtility(UtilityEfficient).
					WithPublicSafetyImpact(PublicSafetyImpactMinimal),
			},
			expected: "SSVCv2/E:A/U:E/T:P/P:M/R:O/0001-01-01T00:00:00Z/",
		},
		{
			given: Vector{
				Stakeholder: StakeholderSupplier,
				Decisions: Decisions{
					Exploitation:    ExploitationActive,
					TechnicalImpact: TechnicalImpactPartial,
				}.ConfigureUtility(AutomatableYes, ValueDensityDiffuse).
					ConfigurePublicSafetyImpact(SafetyImpactMinor),
			},
			expected: "SSVCv2/E:A/A:Y/V:D/U:E/T:P/P:M/R:O/0001-01-01T00:00:00Z/",
		},

		{
			given: Vector{
				Stakeholder: StakeholderDeployer,
				Decisions: Decisions{
					Exploitation: ExploitationActive,
					Exposure:     ExposureControlled,
				}.WithUtility(UtilityEfficient).
					WithHumanImpact(HumanImpactLow),
			},
			expected: "SSVCv2/E:A/X:C/U:E/H:L/P:S/0001-01-01T00:00:00Z/",
		},
		{
			given: Vector{
				Stakeholder: StakeholderDeployer,
				Decisions: Decisions{
					Exploitation: ExploitationActive,
					Exposure:     ExposureControlled,
				}.ConfigureUtility(AutomatableYes, ValueDensityDiffuse).
					ConfigureHumanImpact(SafetyImpactMinor, MissionImpactMissionFailure),
			},
			expected: "SSVCv2/E:A/X:C/A:Y/V:D/U:E/S:M/M:M/H:V/P:O/0001-01-01T00:00:00Z/",
		},
	}
	for i, c := range testCases {
		var actual = c.given.String()
		if actual != c.expected {
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
				r: DefaultVector(StakeholderSupplier),
				v: Vector{
					Decisions: Decisions{
						Exploitation:    ExploitationActive,
						TechnicalImpact: TechnicalImpactTotal,
					},
				},
			},
			expected: Vector{
				Stakeholder: StakeholderSupplier,
				Decisions: Decisions{
					Exploitation:        ExploitationActive,
					_Utility:            UtilityLaborious,
					TechnicalImpact:     TechnicalImpactTotal,
					_PublicSafetyImpact: PublicSafetyImpactMinimal,
				},
			},
		},
		{
			given: input{
				r: DefaultVector(StakeholderSupplier),
				v: Vector{
					Decisions: Decisions{
						Automatable:     AutomatableYes,
						ValueDensity:    ValueDensityDiffuse,
						TechnicalImpact: TechnicalImpactTotal,
					},
				},
			},
			expected: Vector{
				Stakeholder: StakeholderSupplier,
				Decisions: Decisions{
					Exploitation:        ExploitationNone,
					Automatable:         AutomatableYes,
					ValueDensity:        ValueDensityDiffuse,
					_Utility:            "",
					TechnicalImpact:     TechnicalImpactTotal,
					_PublicSafetyImpact: PublicSafetyImpactMinimal,
				},
			},
		},
		{
			given: input{
				r: DefaultVector(StakeholderDeployer),
				v: Vector{
					Decisions: Decisions{
						SafetyImpact:  SafetyImpactMinor,
						MissionImpact: MissionImpactCrippled,
					},
				},
			},
			expected: Vector{
				Stakeholder: StakeholderDeployer,
				Decisions: Decisions{
					Exploitation:  ExploitationNone,
					Exposure:      ExposureSmall,
					_Utility:      UtilityLaborious,
					SafetyImpact:  SafetyImpactMinor,
					MissionImpact: MissionImpactCrippled,
					_HumanImpact:  "",
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

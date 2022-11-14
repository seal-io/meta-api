package ssvc2

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DefaultVector returns a default definition of SSVC(V2) vector.
func DefaultVector(stakeholder Stakeholder) Vector {
	switch stakeholder {
	case StakeholderSupplier:
		return Vector{
			Stakeholder: StakeholderSupplier,
			Decisions: Decisions{
				Exploitation:        ExploitationNone,
				_Utility:            UtilityLaborious,
				TechnicalImpact:     TechnicalImpactPartial,
				_PublicSafetyImpact: PublicSafetyImpactMinimal,
			},
		}
	default:
		return Vector{
			Stakeholder: StakeholderDeployer,
			Decisions: Decisions{
				Exploitation: ExploitationNone,
				Exposure:     ExposureSmall,
				_Utility:     UtilityLaborious,
				_HumanImpact: HumanImpactLow,
			},
		}
	}
}

// ShouldParse likes Parse but without error returning.
func ShouldParse(s string) Vector {
	var p, _ = Parse(s)
	return p
}

// Parse parses Vector from SSVC(V2) vector string.
func Parse(s string) (Vector, error) {
	// for StakeholderSupplier,
	// - SSVCv2/E:P/A:N/V:D/U:L/T:T/P:I/R:I/2022-11-03T11:18:47Z/
	// - SSVCv2/E:P/U:L/T:T/P:I/R:I/2022-11-03T11:18:47Z/ (without sub decision tree)
	// for StakeholderDeployer,
	// - SSVCv2/E:P/X:O/A:N/V:D/U:L/S:N/M:N/H:L/P:D/2022-11-03T07:33:17Z/
	// - SSVCv2/E:P/X:O/U:L/H:L/P:D/2022-11-03T07:33:17Z/ (without sub decision tree)
	const mandatorySize = 8
	s = strings.TrimSpace(s)
	var v Vector
	var parts = strings.Split(s, "/")
	if len(parts) < mandatorySize {
		return Vector{}, fmt.Errorf("illegal SSVC(V2) vector: %s", s)
	}
	for i, part := range parts {
		if i == 0 || i == len(parts)-1 {
			continue
		}
		var dn, dv string
		if i < len(parts)-2 {
			var kv = strings.SplitN(part, ":", 2)
			if len(kv) != 2 {
				return Vector{}, fmt.Errorf("incomplete SSVC(V2) vector: %s", s)
			}
			dn = strings.TrimSpace(kv[0])
			if dn == "" {
				return Vector{}, fmt.Errorf("incomplete SSVC(V2) vector: %s", s)
			}
			dv = strings.TrimSpace(kv[1])
			if dv == "" {
				return Vector{}, fmt.Errorf("incomplete SSVC(V2) vector: %s", s)
			}
		} else {
			dv = part
		}
		switch dn {
		case "E": // Exploitation
			v.Exploitation = Exploitation(dv)
			if !v.Exploitation.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "X": // Exposure
			v.Exposure = Exposure(dv)
			if !v.Exposure.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "A": // Automatable
			v.Automatable = Automatable(dv)
			if !v.Automatable.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "V": // ValueDensity
			v.ValueDensity = ValueDensity(dv)
			if !v.ValueDensity.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "U": // Utility
			v._Utility = Utility(dv)
			if !v._Utility.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "T": // TechnicalImpact
			v.TechnicalImpact = TechnicalImpact(dv)
			if !v.TechnicalImpact.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "P": // PublicSafetyImpact, Priority
			if i == len(parts)-3 { // Priority
				v.Stakeholder = StakeholderDeployer
			} else { // PublicSafetyImpact
				v._PublicSafetyImpact = PublicSafetyImpact(dv)
				if !v._PublicSafetyImpact.isDefined() {
					return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
				}
			}
		case "S": // SafetyImpact
			v.SafetyImpact = SafetyImpact(dv)
			if !v.SafetyImpact.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "M": // MissionImpact
			v.MissionImpact = MissionImpact(dv)
			if !v.MissionImpact.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "H": // HumanImpact
			v._HumanImpact = HumanImpact(dv)
			if !v._HumanImpact.isDefined() {
				return Vector{}, fmt.Errorf("invalid decision '%s' in SSVC(V2) vector: %s", dn, s)
			}
		case "R": // Priority
			if i == len(parts)-3 {
				v.Stakeholder = StakeholderSupplier
			}
		default: // timestamp
			if i == len(parts)-2 {
				v.Timestamp, _ = time.Parse(vectorTimestampFormat, dv)
				if v.Timestamp.IsZero() {
					var secs, err = strconv.ParseInt(dv, 10, 64)
					if err == nil {
						v.Timestamp = time.Unix(secs, 0)
					}
				}
			}
		}
	}

	return v.correct(), nil
}

const vectorTimestampFormat = "2006-01-02T15:04:05Z"

type Decisions struct {
	Exploitation
	Exposure

	Automatable
	ValueDensity
	_Utility Utility

	TechnicalImpact
	SafetyImpact
	_PublicSafetyImpact PublicSafetyImpact
	MissionImpact
	_HumanImpact HumanImpact
}

// Vector holds the decisions vector of SSVC(V2).
type Vector struct {
	Stakeholder
	Decisions
	Timestamp time.Time
}

// ConfigureUtility configures the utility of this SSVC(V2) vector with Automatable and ValueDensity.
func (in Decisions) ConfigureUtility(a Automatable, vd ValueDensity) Decisions {
	in.Automatable = a
	in.ValueDensity = vd
	in._Utility = ""
	return in
}

// WithUtility sets the utility of this SSVC(V2) vector.
func (in Decisions) WithUtility(u Utility) Decisions {
	in.Automatable = ""
	in.ValueDensity = ""
	in._Utility = u
	return in
}

func (in Decisions) getUtility() Utility {
	if in.Automatable.isDefined() && in.ValueDensity.isDefined() {
		return Utility(TreeUtility.MakeDecision(
			string(in.Automatable),
			string(in.ValueDensity)))
	}
	return in._Utility
}

// ConfigurePublicSafetyImpact configures the public safety impact of this SSVC(V2) vector with SafetyImpact.
func (in Decisions) ConfigurePublicSafetyImpact(si SafetyImpact) Decisions {
	in.SafetyImpact = si
	in._PublicSafetyImpact = ""
	return in
}

// WithPublicSafetyImpact sets the public safety impact of this SSVC(V2) vector.
func (in Decisions) WithPublicSafetyImpact(psi PublicSafetyImpact) Decisions {
	in.SafetyImpact = ""
	in._PublicSafetyImpact = psi
	return in
}

func (in Decisions) getPublicSafetyImpact() PublicSafetyImpact {
	if in.SafetyImpact.isDefined() {
		return PublicSafetyImpact(TreePublicSafetyImpact.MakeDecision(
			string(in.SafetyImpact)))
	}
	return in._PublicSafetyImpact
}

// ConfigureHumanImpact configures the human impact of this SSVC(V2) vector with SafetyImpact and MissionImpact.
func (in Decisions) ConfigureHumanImpact(si SafetyImpact, mi MissionImpact) Decisions {
	in.SafetyImpact = si
	in.MissionImpact = mi
	in._HumanImpact = ""
	return in
}

// WithHumanImpact sets the human impact of this SSVC(V2) vector.
func (in Decisions) WithHumanImpact(hi HumanImpact) Decisions {
	in.SafetyImpact = ""
	in.MissionImpact = ""
	in._HumanImpact = hi
	return in
}

func (in Decisions) getHumanImpact() HumanImpact {
	if in.SafetyImpact.isDefined() && in.MissionImpact.isDefined() {
		return HumanImpact(TreeHumanImpact.MakeDecision(
			string(in.SafetyImpact),
			string(in.MissionImpact)))
	}
	return in._HumanImpact
}

// Priority returns the priority(in abbr.) of this SSVC(V2) vector.
func (in Vector) Priority() string {
	var p string
	switch in.Stakeholder {
	case StakeholderSupplier:
		p = TreeSupplier.MakeDecision(
			string(in.Exploitation),
			string(in.getUtility()),
			string(in.TechnicalImpact),
			string(in.getPublicSafetyImpact()))
	default:
		p = TreeDeployer.MakeDecision(
			string(in.Exploitation),
			string(in.Exposure),
			string(in.getUtility()),
			string(in.getHumanImpact()))
	}
	return p
}

// GetVersion returns the ssvc version of this SSVC(V2) vector.
func (in Vector) GetVersion() string {
	return "2.0"
}

// String returns the string format of this SSVC(V2) vector.
func (in Vector) String() string {
	var sb strings.Builder

	// version
	sb.WriteString("SSVCv2/")

	// for StakeholderSupplier,
	// - SSVCv2/E:P/A:N/V:D/U:L/T:T/P:I/R:I/2022-11-03T11:18:47Z/
	// - SSVCv2/E:P/U:L/T:T/P:I/R:I/2022-11-03T11:18:47Z/ (without sub decision tree)
	// for StakeholderDeployer,
	// - SSVCv2/E:P/X:O/A:N/V:D/U:L/S:N/M:N/H:L/P:D/2022-11-03T07:33:17Z/
	// - SSVCv2/E:P/X:O/U:L/H:L/P:D/2022-11-03T07:33:17Z/ (without sub decision tree)
	switch in.Stakeholder {
	case StakeholderSupplier:
		sb.WriteString("E:")
		sb.WriteString(string(in.Exploitation))
		sb.WriteString("/")
		if in.Automatable.isDefined() && in.ValueDensity.isDefined() {
			sb.WriteString("A:")
			sb.WriteString(string(in.Automatable))
			sb.WriteString("/")
			sb.WriteString("V:")
			sb.WriteString(string(in.ValueDensity))
			sb.WriteString("/")
		}
		sb.WriteString("U:")
		sb.WriteString(string(in.getUtility()))
		sb.WriteString("/")
		sb.WriteString("T:")
		sb.WriteString(string(in.TechnicalImpact))
		sb.WriteString("/")
		sb.WriteString("P:")
		sb.WriteString(string(in.getPublicSafetyImpact()))
		sb.WriteString("/")
		sb.WriteString("R:")
		sb.WriteString(string(in.Priority()))
		sb.WriteString("/")
		sb.WriteString(in.Timestamp.Format(vectorTimestampFormat))
		sb.WriteString("/")
	default:
		sb.WriteString("E:")
		sb.WriteString(string(in.Exploitation))
		sb.WriteString("/")
		sb.WriteString("X:")
		sb.WriteString(string(in.Exposure))
		sb.WriteString("/")
		if in.Automatable.isDefined() && in.ValueDensity.isDefined() {
			sb.WriteString("A:")
			sb.WriteString(string(in.Automatable))
			sb.WriteString("/")
			sb.WriteString("V:")
			sb.WriteString(string(in.ValueDensity))
			sb.WriteString("/")
		}
		sb.WriteString("U:")
		sb.WriteString(string(in.getUtility()))
		sb.WriteString("/")
		if in.SafetyImpact.isDefined() && in.MissionImpact.isDefined() {
			sb.WriteString("S:")
			sb.WriteString(string(in.SafetyImpact))
			sb.WriteString("/")
			sb.WriteString("M:")
			sb.WriteString(string(in.MissionImpact))
			sb.WriteString("/")
		}
		sb.WriteString("H:")
		sb.WriteString(string(in.getHumanImpact()))
		sb.WriteString("/")
		sb.WriteString("P:")
		sb.WriteString(string(in.Priority()))
		sb.WriteString("/")
		sb.WriteString(in.Timestamp.Format(vectorTimestampFormat))
		sb.WriteString("/")
	}

	return sb.String()
}

// IsZero returns true if this SSVC(V2) vector is empty,
// DefaultVector is also an empty vector.
func (in Vector) IsZero() bool {
	return in == DefaultVector(in.Stakeholder) || in == Vector{}
}

// Override merges the valued metrics of the given Vector.
func (in Vector) Override(i Vector) (v Vector) {
	v = in

	if i.Stakeholder != "" {
		v.Stakeholder = i.Stakeholder
	}

	if i.Exploitation != "" {
		v.Exploitation = i.Exploitation
	}
	if i.Exposure != "" {
		v.Exposure = i.Exposure
	}

	if i.Automatable != "" {
		v.Automatable = i.Automatable
	}
	if i.ValueDensity != "" {
		v.ValueDensity = i.ValueDensity
	}
	if i._Utility != "" {
		v._Utility = i._Utility
	}

	if i.TechnicalImpact != "" {
		v.TechnicalImpact = i.TechnicalImpact
	}
	if i.SafetyImpact != "" {
		v.SafetyImpact = i.SafetyImpact
	}
	if i._PublicSafetyImpact != "" {
		v._PublicSafetyImpact = i._PublicSafetyImpact
	}
	if i.MissionImpact != "" {
		v.MissionImpact = i.MissionImpact
	}
	if i._HumanImpact != "" {
		v._HumanImpact = i._HumanImpact
	}

	if !i.Timestamp.IsZero() {
		v.Timestamp = i.Timestamp
	}

	return v.correct()
}

func (in Vector) correct() Vector {
	switch in.Stakeholder {
	case StakeholderSupplier:
		if in.Automatable.isDefined() && in.ValueDensity.isDefined() {
			in._Utility = ""
		} else {
			in.Automatable = ""
			in.ValueDensity = ""
		}
		if in.SafetyImpact.isDefined() {
			in._PublicSafetyImpact = ""
		} else {
			in.SafetyImpact = ""
		}
	case StakeholderDeployer:
		if in.Automatable.isDefined() && in.ValueDensity.isDefined() {
			in._Utility = ""
		} else {
			in.Automatable = ""
			in.ValueDensity = ""
		}
		if in.SafetyImpact.isDefined() && in.MissionImpact.isDefined() {
			in._HumanImpact = ""
		} else {
			in.SafetyImpact = ""
			in.MissionImpact = ""
		}
	}
	return in
}

// Stakeholder of SSVC(V2) vector.
type Stakeholder string

// constants of Stakeholder.
const (
	StakeholderSupplier Stakeholder = "supplier"
	StakeholderDeployer Stakeholder = "deployer"
)

func (in Stakeholder) isDefined() bool {
	switch in {
	default:
		return false
	case StakeholderSupplier:
	case StakeholderDeployer:
	}
	return true
}

// Exploitation of SSVC(V2) vector, abbreviates as 'E',
// it means the evidence of active exploitation of a vulnerability.
type Exploitation string

// constants of Exploitation.
const (
	// ExploitationNone means there is no evidence of active exploitation and no public proof of concept (PoC) of how to exploit the vulnerability.
	ExploitationNone Exploitation = "N"

	// ExploitationPoC means one of the following cases is true:
	//  - (1) private evidence of exploitation is attested but not shared;
	//  - (2) widespread hearsay attests to exploitation;
	//  - (3) typical public PoC in places such as Metasploit or ExploitDB;
	//  - (4) the vulnerability has a well-known method of exploitation.
	// Some examples of condition (4) are open-source web proxies serve as the PoC code for how to exploit any vulnerability in the vein of improper validation of TLS certificates. As another example, Wireshark serves as a PoC for packet replay attacks on ethernet or WiFi networks.
	ExploitationPoC Exploitation = "P"

	// ExploitationActive means shared, observable, reliable evidence that the exploit is being used in the wild by real attackers; there is credible public reporting.
	ExploitationActive Exploitation = "A"
)

func (in Exploitation) isDefined() bool {
	switch in {
	default:
		return false
	case ExploitationNone:
	case ExploitationPoC:
	case ExploitationActive:
	}
	return true
}

// Exposure of SSVC(V2) vector, abbreviates as 'X',
// it means the accessible attack surface of the affected system or service.
type Exposure string

// constants of Exposure.
const (
	// ExposureSmall means local service or program; highly controlled network.
	ExposureSmall Exposure = "S"

	// ExposureControlled means networked service with some access restrictions or mitigations already in place (whether locally or on the network). A successful mitigation must reliably interrupt the adversary's attack, which requires the attack is detectable both reliably and quickly enough to respond. Controlled covers the situation in which a vulnerability can be exploited through chaining it with other vulnerabilities. The assumption is that the number of steps in the attack path is relatively low; if the path is long enough that it is implausible for an adversary to reliably execute it, then exposure should be small.
	ExposureControlled Exposure = "C"

	// ExposureOpen means internet or another widely accessible network where access cannot plausibly be restricted or controlled (e.g., DNS servers, web servers, VOIP servers, email servers).
	ExposureOpen Exposure = "O"
)

func (in Exposure) isDefined() bool {
	switch in {
	default:
		return false
	case ExposureSmall:
	case ExposureControlled:
	case ExposureOpen:
	}
	return true
}

// types of Utility group.
type (
	// Automatable of SSVC(V2) vector, abbreviates as 'A', is a part of Utility,
	// it captures the answer to the question "Can an attacker reliably automate creating exploitation events for this vulnerability?".
	Automatable string

	// ValueDensity of SSVC(V2) vector, abbreviates as 'V', is a part of Utility,
	// it means the resources that the adversary will gain control over with a single exploitation event.
	ValueDensity string

	// Utility of SSVC(V2) vector, abbreviates as 'U', estimates an adversary's benefit compared to their effort based on the assumption that they can exploit the vulnerability.
	Utility string
)

// constants of Utility group.
const (
	// AutomatableNo means steps 1-4 of the kill chain  cannot be reliably automated for this vulnerability for some reason. These steps are reconnaissance, weaponization, delivery, and exploitation. Example reasons for why a step may not be reliably automatable include,
	//  - (1) the vulnerable component is not searchable or enumerable on the network,
	//  - (2) weaponization may require human direction for each target,
	//  - (3) delivery may require channels that widely deployed network security configurations block,
	//  - (4) exploitation may be frustrated by adequate exploit-prevention techniques enabled by default;
	// ASLR is an example of an exploit-prevention tool.
	AutomatableNo Automatable = "N"

	// AutomatableYes means steps 1-4 of the kill chain can be reliably automated.
	// If the vulnerability allows unauthenticated remote code execution (RCE) or command injection, the response is likely yes.
	AutomatableYes Automatable = "Y"

	// ValueDensityDiffuse means the system that contains the vulnerable component has limited resources.
	// That is, the resources that the adversary will gain control over with a single exploitation event are relatively small.
	// Examples of systems with diffuse value are email accounts, most consumer online banking accounts, common cell phones, and most personal computing resources owned and maintained by users. (A "user" is anyone whose professional task is something other than the maintenance of the system or component. As with Safety Impact, a "system operator" is anyone who is professionally responsible for the proper operation or maintenance of a system.).
	ValueDensityDiffuse ValueDensity = "D"

	// ValueDensityConcentrated means the system that contains the vulnerable component is rich in resources.
	// Heuristically, such systems are often the direct responsibility of "system operators" rather than users.
	// Examples of concentrated value are database systems, Kerberos servers, web servers hosting login pages, and cloud service providers. However, usefulness and uniqueness of the resources on the vulnerable system also inform value density. For example, encrypted mobile messaging platforms may have concentrated value, not because each phone's messaging history has a particularly large amount of data, but because it is uniquely valuable to law enforcement.
	ValueDensityConcentrated ValueDensity = "C"

	// UtilityLaborious means no to automatable and diffuse value.
	UtilityLaborious Utility = "L"

	// UtilityEfficient means {yes to automatable and diffuse value} or {no to automatable and concentrated value}.
	UtilityEfficient Utility = "E"

	// UtilitySuperEffective means yes to automatable and concentrated value.
	UtilitySuperEffective Utility = "S"
)

func (in Automatable) isDefined() bool {
	switch in {
	default:
		return false
	case AutomatableNo:
	case AutomatableYes:
	}
	return true
}

func (in ValueDensity) isDefined() bool {
	switch in {
	default:
		return false
	case ValueDensityDiffuse:
	case ValueDensityConcentrated:
	}
	return true
}

func (in Utility) isDefined() bool {
	switch in {
	default:
		return false
	case UtilityLaborious:
	case UtilityEfficient:
	case UtilitySuperEffective:
	}
	return true
}

// TechnicalImpact of SSVC(V2) vector, abbreviates as 'T',
// it means the technical impact of exploiting the vulnerability.
type TechnicalImpact string

// constants of TechnicalImpact.
const (
	// TechnicalImpactPartial means the exploit gives the adversary limited control over, or information exposure about, the behavior of the software that contains the vulnerability.
	// Or the exploit gives the adversary an importantly low stochastic opportunity for total control.
	// In this context, "low" means that the attacker cannot reasonably make enough attempts to overcome the low chance of each attempt not working.
	// Denial of service is a form of limited control over the behavior of the vulnerable component.
	TechnicalImpactPartial TechnicalImpact = "P"

	// TechnicalImpactTotal means the exploit gives the adversary total control over the behavior of the software,
	// or it gives total disclosure of all information on the system that contains the vulnerability.
	TechnicalImpactTotal TechnicalImpact = "T"
)

func (in TechnicalImpact) isDefined() bool {
	switch in {
	default:
		return false
	case TechnicalImpactPartial:
	case TechnicalImpactTotal:
	}
	return true
}

// SafetyImpact of SSVC(V2) vector, abbreviates as 'S', is a part of PublicSafetyImpact or HumanImpact,
// it means the safety impacts of affected system compromise.
type SafetyImpact string

// constants of SafetyImpact.
const (
	// SafetyImpactNone does not mean no impact literally;
	// the effect is below the threshold for all aspects described in SituatedSafetyImpactMinor.
	SafetyImpactNone SafetyImpact = "N"

	// SafetyImpactMinor means any one of the following is observed,
	//  - "Physical Harm": Physical discomfort for users of the system OR a minor occupational safety hazard OR reduction in physical system safety margins.
	//  - "Environment": Minor externalities (property damage, environmental damage, etc.) imposed on other parties.
	//  - "Financial": Financial losses, which are not readily absorbable, to multiple persons.
	//  - "Psychological": Emotional or psychological harm, sufficient to be caused for counseling or therapy, to multiple persons.
	SafetyImpactMinor SafetyImpact = "M"

	// SafetyImpactMajor means any one of the following is observed,
	//  - "Physical Harm": Physical distress and injuries for users of the system OR a significant occupational safety hazard OR failure of physical system functional capabilities that support safe operation.
	//  - "Environment": Major externalities (property damage, environmental damage, etc.) imposed on other parties.
	//  - "Financial": Financial losses that likely lead to bankruptcy of multiple persons.
	//  - "Psychological": Widespread emotional or psychological harm, sufficient to be caused for counseling or therapy, to populations of people.
	SafetyImpactMajor SafetyImpact = "A"

	// SafetyImpactHazardous means any one of the following is observed,
	//  - "Physical Harm": Serious or fatal injuries, where fatalities are plausibly preventable via emergency services or other measures OR parts of the cyber-physical system that support safe operation break.
	//  - "Environment": Serious externalities (threat to life as well as property, widespread environmental damage, measurable public health risks, etc.) imposed on other parties.
	//  - "Financial": Socio-technical system (elections, financial grid, etc.) of which the affected component is a part is actively destabilized and enters unsafe state.
	//  - Psychological: N/A.
	SafetyImpactHazardous SafetyImpact = "H"

	// SafetyImpactCatastrophic means any one of the following is observed,
	//  - "Physical Harm": Multiple immediate fatalities (emergency response probably cannot save the victims.).
	//  - "Environment": Extreme externalities (immediate public health threat, environmental damage leading to small ecosystem collapse, etc.) imposed on other parties.
	//  - "Financial": Social systems (elections, financial grid, etc.) supported by the software collapse.
	//  - "Psychological": N/A.
	SafetyImpactCatastrophic SafetyImpact = "C"
)

func (in SafetyImpact) isDefined() bool {
	switch in {
	default:
		return false
	case SafetyImpactNone:
	case SafetyImpactMinor:
	case SafetyImpactMajor:
	case SafetyImpactHazardous:
	case SafetyImpactCatastrophic:
	}
	return true
}

// PublicSafetyImpact of SSVC(V2) vector, abbreviates as 'P',
// it means the perspective of StakeholderSupplier for SafetyImpact.
type PublicSafetyImpact string

const (
	// PublicSafetyImpactMinimal means safety impacts of affected system compromise is SafetyImpactNone or SafetyImpactMinor.
	PublicSafetyImpactMinimal PublicSafetyImpact = "M"

	// PublicSafetyImpactSignificant means safety impacts of affected system compromise is SafetyImpactMajor, SafetyImpactHazardous or SafetyImpactCatastrophic.
	PublicSafetyImpactSignificant PublicSafetyImpact = "I"
)

func (in PublicSafetyImpact) isDefined() bool {
	switch in {
	default:
		return false
	case PublicSafetyImpactMinimal:
	case PublicSafetyImpactSignificant:
	}
	return true
}

// types of HumanImpact group.
type (
	// MissionImpact of SSVC(V2) vector, abbreviates as 'M', is a part of HumanImpact,
	// it means the impact on mission essential functions of the organization.
	MissionImpact string

	// HumanImpact of SSVC(V2) vector, abbreviates as 'H',
	// it is combined SituatedSafetyImpact and MissionImpact.
	HumanImpact string
)

// constants of HumanImpact group.
const (
	// MissionImpactNone means little to no impact up to degradation of non-essential functions.
	MissionImpactNone MissionImpact = "N"

	// MissionImpactDegraded chronic degradation would eventually harm essential functions.
	MissionImpactDegraded MissionImpact = "D"

	// MissionImpactCrippled means Mission Essential Function (MEF) support is crippled.
	// Activities that directly support essential functions are crippled; essential functions continue for a time.
	MissionImpactCrippled MissionImpact = "C"

	// MissionImpactMEFFailure means any one mission essential function fails for period of time longer than acceptable;
	// overall mission of the organization degraded but can still be accomplished for a time.
	MissionImpactMEFFailure MissionImpact = "F"

	// MissionImpactMissionFailure means multiple or all mission essential functions fail;
	// ability to recover those functions degraded;
	// organization's ability to deliver its overall mission fails.
	MissionImpactMissionFailure MissionImpact = "M"

	// HumanImpactLow means the combined SituatedSafetyImpact and MissionImpact is "low".
	HumanImpactLow HumanImpact = "L"

	// HumanImpactMedium means the combined SituatedSafetyImpact and MissionImpact is "medium".
	HumanImpactMedium HumanImpact = "M"

	// HumanImpactHigh means the combined SituatedSafetyImpact and MissionImpact is "high".
	HumanImpactHigh HumanImpact = "H"

	// HumanImpactVeryHigh means the combined SituatedSafetyImpact and MissionImpact is "very high".
	HumanImpactVeryHigh HumanImpact = "V"
)

func (in MissionImpact) isDefined() bool {
	switch in {
	default:
		return false
	case MissionImpactNone:
	case MissionImpactDegraded:
	case MissionImpactCrippled:
	case MissionImpactMEFFailure:
	case MissionImpactMissionFailure:
	}
	return true
}

func (in HumanImpact) isDefined() bool {
	switch in {
	default:
		return false
	case HumanImpactLow:
	case HumanImpactMedium:
	case HumanImpactHigh:
	case HumanImpactVeryHigh:
	}
	return true
}

// Priority of SSVC(V2) vector, abbreviates as 'P'(on StakeholderDeployer side) or 'R'(on StakeholderSupplier side),
// it means the action should take after decision.
type Priority = string

const (
	// PriorityDefer means as below,
	//  - for StakeholderDeployer, it means do not act at present.
	//  - for StakeholderSupplier, it means do not work on the patch at present.
	PriorityDefer Priority = "D"

	// PriorityScheduled means as below,
	//  - for StakeholderDeployer, it means that act during regularly scheduled maintenance time.
	//  - for StakeholderSupplier, it means that develop a fix within regularly scheduled maintenance using supplier resources as normal.
	PriorityScheduled Priority = "S"

	// PriorityOutOfCycle means as below,
	//  - for StakeholderDeployer, it means that act more quickly than usual to apply the mitigation or remediation out-of-cycle, during the next available opportunity, working overtime if necessary.
	//  - for StakeholderSupplier, it means that develop mitigation or remediation out-of-cycle, taking resources away from other projects and releasing the fix as a security patch when it is ready.
	PriorityOutOfCycle Priority = "O"

	// PriorityImmediate means as below,
	//  - for StakeholderDeployer, it means that act immediately, focus all resources on applying the fix as quickly as possible, including, if necessary, pausing regular organization operations.
	//  - for StakeholderSupplier, it means that develop and release a fix as quickly as possible, drawing on all available resources, potentially including drawing on or coordinating resources from other parts of the organization.
	PriorityImmediate Priority = "I"
)

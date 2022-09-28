package distro

import (
	"strings"
)

// updated by https://wiki.ubuntu.com/Releases.
var ubuntuVersionCodename = map[string]string{
	"4.10":  "warty",
	"5.04":  "hoary",
	"5.10":  "breezy",
	"6.06":  "dapper",
	"6.10":  "edgy",
	"7.04":  "feisty",
	"7.10":  "gutsy",
	"8.04":  "hardy",
	"8.10":  "intrepid",
	"9.04":  "jaunty",
	"9.10":  "karmic",
	"10.04": "lucid",
	"10.10": "maverick",
	"11.04": "natty",
	"11.10": "oneiric",
	"12.04": "precise",
	"12.10": "quantal",
	"13.04": "raring",
	"13.10": "saucy",
	"14.04": "trusty",
	"14.10": "utopic",
	"15.04": "vivid",
	"15.10": "wily",
	"16.04": "xenial",
	"16.10": "yakkety",
	"17.04": "zesty",
	"17.10": "artful",
	"18.04": "bionic",
	"18.10": "cosmic",
	"19.04": "disco",
	"19.10": "eoan",
	"20.04": "focal",
	"20.10": "groovy",
	"21.04": "hirsute",
	"21.10": "impish",
	"22.04": "jammy",
	"22.10": "kinetic",
}

var ubuntuCodenameVersion = make(map[string]string, len(ubuntuVersionCodename))

func init() {
	for version, codename := range ubuntuVersionCodename {
		ubuntuCodenameVersion[codename] = version
	}
}

const UbuntuDevelopmentCodename = "adjective"

// GetUbuntuCodenameByVersion returns codename by version.
func GetUbuntuCodenameByVersion(v string) string {
	var codename = ubuntuVersionCodename[NormalizeUbuntuVersion(v)]
	if codename != "" {
		return codename
	}
	return UbuntuDevelopmentCodename
}

const UbuntuDevelopmentVersion = "devel"

// GetUbuntuVersionByCodename returns version by codename.
func GetUbuntuVersionByCodename(c string) string {
	var version = ubuntuCodenameVersion[NormalizeUbuntuCodename(c)]
	if version != "" {
		return version
	}
	return UbuntuDevelopmentVersion
}

// NormalizeUbuntuCodename parses the codename line of `lsb_release -a` output.
func NormalizeUbuntuCodename(s string) string {
	s = strings.ToLower(s)
	var ss = strings.SplitN(s, " ", 2)
	return ss[0]
}

// NormalizeUbuntuVersion parses the description/release line of `lsb_release -a` output.
func NormalizeUbuntuVersion(s string) string {
	s = extractVersion(s)
	if s != "" && s[0] == 'v' {
		s = s[1:]
	}
	var ss = strings.Split(s, ".")
	if len(ss) >= 2 {
		return ss[0] + "." + ss[1]
	}
	return s
}

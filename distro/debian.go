package distro

import (
	"strconv"
	"strings"
)

// updated by https://www.debian.org/doc/manuals/debian-faq/ftparchives#sourceforcodenames.
var debianVersionCodename = map[string]string{
	"1.1": "buzz",
	"1.2": "rex",
	"1.3": "bo",
	"2.0": "hamm",
	"2.1": "slink",
	"2.2": "potato",
	"3.0": "woody",
	"3.1": "sarge",
	"4.0": "etch",
	"5.0": "lenny",
	"6":   "squeeze",
	"7":   "wheezy",
	"8":   "jessie",
	"9":   "stretch",
	"10":  "buster",
	"11":  "bullseye",
	"12":  "bookworm",
	"13":  "trixie",
}

var debianCodenameVersion = make(map[string]string, len(debianVersionCodename))

func init() {
	for version, codename := range debianVersionCodename {
		debianCodenameVersion[codename] = version
	}
}

const DebianDevelopmentCodename = "sid"

// GetDebianCodenameByVersion returns codename by version.
func GetDebianCodenameByVersion(v string) string {
	var codename = debianVersionCodename[NormalizeDebianVersion(v)]
	if codename != "" {
		return codename
	}
	return DebianDevelopmentCodename
}

const DebianDevelopmentVersion = "unstable"

// GetDebianVersionByCodename returns version by codename.
func GetDebianVersionByCodename(c string) string {
	var version = debianCodenameVersion[NormalizeDebianCodename(c)]
	if version != "" {
		return version
	}
	return DebianDevelopmentVersion
}

// NormalizeDebianCodename parses the codename line of `lsb_release -a` output.
func NormalizeDebianCodename(s string) string {
	s = strings.ToLower(s)
	var ss = strings.SplitN(s, " ", 2)
	return ss[0]
}

// NormalizeDebianVersion parses the description/release line of `lsb_release -a` output.
func NormalizeDebianVersion(s string) string {
	s = extractVersion(s)
	if s != "" && s[0] == 'v' {
		s = s[1:]
	}
	var ss = strings.Split(s, ".")
	if len(ss) >= 2 {
		var major, err = strconv.ParseInt(ss[0], 10, 32)
		if err != nil {
			return s
		}
		if major >= 6 {
			return ss[0]
		}
		return ss[0] + "." + ss[1]
	}
	return s
}

package distro

import "regexp"

const versionRegexPattern string = `([0-9]+)(\.[0-9]+)?(\.[0-9]+)?` +
	`(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?` +
	`(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?`

var versionRegex = regexp.MustCompile(versionRegexPattern)

// extractVersion extracts the version from the given string.
func extractVersion(s string) string {
	return versionRegex.FindString(s)
}

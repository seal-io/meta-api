package distro

import "testing"

func TestNormalizeDebianCodename(t *testing.T) {
	var testCases = []struct {
		given    string
		expected string
	}{
		{
			given:    "stretch",
			expected: "stretch",
		},
		{
			given:    "Stretch",
			expected: "stretch",
		},
	}

	for _, c := range testCases {
		var actual = NormalizeDebianCodename(c.given)
		if actual != c.expected {
			t.Errorf("NormalizeDebianCodename(%s) == %s, but got %s", c.given, c.expected, actual)
		}
	}
}

func TestNormalizeDebianVersion(t *testing.T) {
	var testCases = []struct {
		given    string
		expected string
	}{
		{
			given:    "Debian GNU/Linux 9.5 (stretch)",
			expected: "9",
		},
		{
			given:    "Debian GNU/Linux 6.0.10 (squeeze)",
			expected: "6",
		},
		{
			given:    "Linux 9.5",
			expected: "9",
		},
		{
			given:    "v9.5",
			expected: "9",
		},
		{
			given:    "not found",
			expected: "",
		},
	}

	for _, c := range testCases {
		var actual = NormalizeDebianVersion(c.given)
		if actual != c.expected {
			t.Errorf("NormalizeUbuntuVersion(%s) == %s, but got %s", c.given, c.expected, actual)
		}
	}
}

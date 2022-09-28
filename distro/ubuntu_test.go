package distro

import "testing"

func TestNormalizeUbuntuCodename(t *testing.T) {
	var testCases = []struct {
		given    string
		expected string
	}{
		{
			given:    "focal",
			expected: "focal",
		},
		{
			given:    "Focal Fossa",
			expected: "focal",
		},
		{
			given:    "focal fossa",
			expected: "focal",
		},
	}

	for _, c := range testCases {
		var actual = NormalizeUbuntuCodename(c.given)
		if actual != c.expected {
			t.Errorf("NormalizeUbuntuCodename(%s) == %s, but got %s", c.given, c.expected, actual)
		}
	}
}

func TestNormalizeUbuntuVersion(t *testing.T) {
	var testCases = []struct {
		given    string
		expected string
	}{
		{
			given:    "Ubuntu 20.04.3 LTS",
			expected: "20.04",
		},
		{
			given:    "20.04 LTS",
			expected: "20.04",
		},
		{
			given:    "20.04 lts",
			expected: "20.04",
		},
		{
			given:    "20.04",
			expected: "20.04",
		},
		{
			given:    "v20.04",
			expected: "20.04",
		},
		{
			given:    "not found",
			expected: "",
		},
	}

	for _, c := range testCases {
		var actual = NormalizeUbuntuVersion(c.given)
		if actual != c.expected {
			t.Errorf("NormalizeUbuntuVersion(%s) == %s, but got %s", c.given, c.expected, actual)
		}
	}
}

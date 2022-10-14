package genver

import "testing"

func TestIsUnboundedRange(t *testing.T) {
	var testCases = []struct {
		given    string
		expected bool
	}{
		{
			given:    "",
			expected: false,
		},
		{
			given:    ">=v0.2.0",
			expected: true,
		},
		{
			given:    "<v0.6.0",
			expected: true,
		},
		{
			given:    "=0.1.0||>0.2.0,<0.3.0",
			expected: false,
		},
	}
	for _, c := range testCases {
		var actual = IsUnboundedRange(c.given)
		if actual != c.expected {
			t.Errorf("unexpected result of IsUnboundedRange(%s), expected: %v, actual: %v", c.given, c.expected, actual)
		}
	}
}

func TestRestrictUnboundedRange(t *testing.T) {
	type input struct {
		w     string
		ubrng string
	}
	type output struct {
		r  string
		ok bool
	}
	var testCases = []struct {
		given    input
		expected output
	}{
		{
			given: input{
				w:     "",
				ubrng: ">=0.0",
			},
			expected: output{
				r:  "",
				ok: false,
			},
		},
		{
			given: input{
				w:     "3.2.2",
				ubrng: "",
			},
			expected: output{
				r:  "",
				ok: false,
			},
		},
		{
			given: input{
				w:     "6.9",
				ubrng: "<6.0.3",
			},
			expected: output{
				r:  "",
				ok: false,
			},
		},
		{
			given: input{
				w:     "5.0",
				ubrng: ">=6.0.3",
			},
			expected: output{
				r:  "",
				ok: false,
			},
		},
		{
			given: input{
				w:     "5.0",
				ubrng: "=0.1.0||>0.2.0,<0.3.0",
			},
			expected: output{
				r:  "",
				ok: false,
			},
		},
		{
			given: input{
				w:     "3.2.2",
				ubrng: "<6.0.3-v4",
			},
			expected: output{
				r:  ">=3.2.2,<6.0.3-v4",
				ok: true,
			},
		},
		{
			given: input{
				w:     "3.2.2",
				ubrng: ">0.0",
			},
			expected: output{
				r:  ">0.0,<=3.2.2",
				ok: true,
			},
		},
	}
	for _, c := range testCases {
		var actual output
		actual.r, actual.ok = RestrictUnboundedRange(c.given.w, c.given.ubrng)
		if actual != c.expected {
			t.Errorf("unexpected result of RestrictUnboundedRange(%s, %s), expected: %v, actual: %v", c.given.w, c.given.ubrng, c.expected, actual)
		}
	}
}

package ssvc2

import (
	"reflect"
	"testing"
)

func TestTree_MakeDecision(t *testing.T) {
	type input struct {
		name  string
		paths []string
	}
	var testCases = []struct {
		given    input
		expected string
	}{
		{
			given: input{
				name:  "TreeHumanImpact",
				paths: []string{"N", "N"},
			},
			expected: "L",
		},
		{
			given: input{
				name:  "TreeHumanImpact",
				paths: []string{"N", "F"},
			},
			expected: "M",
		},
		{
			given: input{
				name:  "TreeHumanImpact",
				paths: []string{"A", "F"},
			},
			expected: "H",
		},
		{
			given: input{
				name:  "TreeHumanImpact",
				paths: []string{"N", "M"},
			},
			expected: "V",
		},

		{
			given: input{
				name:  "TreePublicSafetyImpact",
				paths: []string{"N"},
			},
			expected: "M",
		},
		{
			given: input{
				name:  "TreePublicSafetyImpact",
				paths: []string{"A"},
			},
			expected: "I",
		},

		{
			given: input{
				name:  "TreeUtility",
				paths: []string{"N", "D"},
			},
			expected: "L",
		},
		{
			given: input{
				name:  "TreeUtility",
				paths: []string{"N", "C"},
			},
			expected: "E",
		},
		{
			given: input{
				name:  "TreeUtility",
				paths: []string{"Y", "C"},
			},
			expected: "S",
		},

		{
			given: input{
				name:  "TreeDeployer",
				paths: []string{"N", "O", "L", "L"},
			},
			expected: "D",
		},
		{
			given: input{
				name:  "TreeDeployer",
				paths: []string{"N", "O", "E", "H"},
			},
			expected: "S",
		},
		{
			given: input{
				name:  "TreeDeployer",
				paths: []string{"P", "C", "S", "V"},
			},
			expected: "O",
		},
		{
			given: input{
				name:  "TreeDeployer",
				paths: []string{"A", "O", "S", "H"},
			},
			expected: "I",
		},

		{
			given: input{
				name:  "TreeSupplier",
				paths: []string{"N", "L", "P", "M"},
			},
			expected: "D",
		},
		{
			given: input{
				name:  "TreeSupplier",
				paths: []string{"N", "S", "P", "M"},
			},
			expected: "S",
		},
		{
			given: input{
				name:  "TreeSupplier",
				paths: []string{"P", "E", "T", "M"},
			},
			expected: "O",
		},
		{
			given: input{
				name:  "TreeSupplier",
				paths: []string{"A", "S", "T", "I"},
			},
			expected: "I",
		},
	}
	for i, c := range testCases {
		var tree Node
		switch c.given.name {
		case "TreeHumanImpact":
			tree = TreeHumanImpact
		case "TreePublicSafetyImpact":
			tree = TreePublicSafetyImpact
		case "TreeUtility":
			tree = TreeUtility
		case "TreeDeployer":
			tree = TreeDeployer
		case "TreeSupplier":
			tree = TreeSupplier
		}
		var actual = tree.MakeDecision(c.given.paths...)
		if actual != c.expected {
			t.Errorf("case %d: %s.MakeDecision(%v) expected %s, but got %s",
				i+1, c.given.name, c.given.paths, c.expected, actual)
		}
	}
}

func TestTree_NextSteps(t *testing.T) {
	type input struct {
		name  string
		paths []string
	}
	var testCases = []struct {
		given    input
		expected []string
	}{
		{
			given: input{
				name:  "TreeHumanImpact",
				paths: []string{"N"},
			},
			expected: []string{"N", "D", "C", "F", "M"},
		},
		{
			given: input{
				name:  "TreeHumanImpact",
				paths: []string{"N", "M"},
			},
			expected: []string{"V"},
		},

		{
			given: input{
				name:  "TreePublicSafetyImpact",
				paths: []string{"M"},
			},
			expected: []string{"M"},
		},
		{
			given: input{
				name:  "TreePublicSafetyImpact",
				paths: []string{"A"},
			},
			expected: []string{"I"},
		},

		{
			given: input{
				name:  "TreeUtility",
				paths: []string{"N"},
			},
			expected: []string{"D", "C"},
		},
		{
			given: input{
				name:  "TreeUtility",
				paths: []string{"Y", "D"},
			},
			expected: []string{"E"},
		},

		{
			given: input{
				name:  "TreeDeployer",
				paths: []string{"A"},
			},
			expected: []string{"S", "C", "O"},
		},
		{
			given: input{
				name:  "TreeDeployer",
				paths: []string{"A", "S", "E"},
			},
			expected: []string{"L", "M", "H", "V"},
		},

		{
			given: input{
				name:  "TreeSupplier",
				paths: []string{"P"},
			},
			expected: []string{"L", "E", "S"},
		},
		{
			given: input{
				name:  "TreeSupplier",
				paths: []string{"A", "E", "P"},
			},
			expected: []string{"M", "I"},
		},
	}
	for i, c := range testCases {
		var tree Node
		switch c.given.name {
		case "TreeHumanImpact":
			tree = TreeHumanImpact
		case "TreePublicSafetyImpact":
			tree = TreePublicSafetyImpact
		case "TreeUtility":
			tree = TreeUtility
		case "TreeDeployer":
			tree = TreeDeployer
		case "TreeSupplier":
			tree = TreeSupplier
		}
		var actual = tree.NextSteps(c.given.paths...)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("case %d: %s.MakeDecision(%v) expected %v, but got %v",
				i+1, c.given.name, c.given.paths, c.expected, actual)
		}
	}
}

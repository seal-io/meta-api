package ssvc2

import (
	"bytes"
	"embed"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
)

//go:embed trees/*
var trees embed.FS
var (
	// TreeHumanImpact makes decision by SafetyImpact, MissionImpact.
	TreeHumanImpact = mustParseTree(trees.ReadFile("trees/p_human_impact.csv"))
	// TreePublicSafetyImpact makes decision by SafetyImpact.
	TreePublicSafetyImpact = mustParseTree(trees.ReadFile("trees/p_public_safety_impact.csv"))
	// TreeUtility makes decision by Automatable, ValueDensity.
	TreeUtility = mustParseTree(trees.ReadFile("trees/p_utility.csv"))
	// TreeDeployer makes decision by Exploitation, Exposure, Utility, HumanImpact.
	TreeDeployer = mustParseTree(trees.ReadFile("trees/t_deployer.csv"))
	// TreeSupplier makes decision by Exploitation, Utility, TechnicalImpact, PublicSafetyImpact.
	TreeSupplier = mustParseTree(trees.ReadFile("trees/t_supplier.csv"))
)

type Node interface {
	// NextSteps returns the next steps by the given paths.
	NextSteps(paths ...string) []string

	// MakeDecision returns the destination by the given paths,
	// or returns blank if the given paths cannot point to one clear destination.
	MakeDecision(paths ...string) string
}

type (
	node struct {
		parent            *node
		childValueNodeMap map[string]*node
		childValues       []string
		key               string
		value             string
	}
)

func (in node) setPath(paths []string, captions []string) {
	var p = &in
	for i, path := range paths {
		if p.childValueNodeMap[path] == nil {
			p.childValueNodeMap[path] = &node{
				parent:            p,
				childValueNodeMap: map[string]*node{},
				key:               captions[i],
				value:             path,
			}
			p.childValues = append(p.childValues, path)
		}
		p = p.childValueNodeMap[path]
	}
}

func (in node) NextSteps(paths ...string) []string {
	var p = &in
	for _, path := range paths {
		if p.childValueNodeMap[path] == nil {
			return nil
		}
		p = p.childValueNodeMap[path]
	}
	return append(make([]string, 0, len(p.childValues)), p.childValues...)
}

func (in node) MakeDecision(paths ...string) string {
	var p = &in
	for _, path := range paths {
		if p.childValueNodeMap[path] == nil {
			return ""
		}
		p = p.childValueNodeMap[path]
	}
	if len(p.childValues) == 1 {
		return p.childValues[0]
	}
	return ""
}

// ParseTree returns a decision tree by the given CSV content.
func ParseTree(csvBytes []byte) (Node, error) {
	var r = csv.NewReader(bytes.NewReader(csvBytes))
	r.TrimLeadingSpace = true
	var captions, err = r.Read()
	if err != nil {
		return node{}, fmt.Errorf("error reading caption: %w", err)
	}

	var t = node{
		childValueNodeMap: map[string]*node{},
	}
	for {
		var paths, err = r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return node{}, fmt.Errorf("error reading path: %w", err)
		}
		if len(paths) != len(captions) {
			return node{}, fmt.Errorf("invalid length of path, expected %d, but got %d", len(captions), len(paths))
		}
		t.setPath(paths, captions)
	}

	return t, nil
}

func mustParseTree(csvBytes []byte, err error) Node {
	if err != nil {
		panic(err)
	}

	t, err := ParseTree(csvBytes)
	if err != nil {
		panic(err)
	}
	return t
}

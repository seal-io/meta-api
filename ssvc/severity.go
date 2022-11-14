package ssvc

import "strings"

// GetPriorityNumber returns number of the given priority,
// it doesn't return the actual score of the priority but instead of a numeric value,
// which can be used for comparing.
func GetPriorityNumber(p string) int {
	p = strings.ToUpper(p)
	if p != "" {
		p = p[:1]
	}
	switch p {
	case "I":
		return 4
	case "O":
		return 3
	case "S":
		return 2
	case "D":
		return 1
	default:
		return 0
	}
}

// ComparePriority returns an integer comparing two priority.
// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
func ComparePriority(v, w string) int {
	var vs = GetPriorityNumber(v)
	var ws = GetPriorityNumber(w)
	var s = vs - ws
	if s > 0 {
		return +1
	}
	if s < 0 {
		return -1
	}
	return 0
}

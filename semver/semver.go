package semver

import (
	"strings"
)

type op = uint8

const (
	eq op = iota + 1
	lt
	gt
	le
	ge
)

func eval(l string, op op, r string) bool {
	switch op {
	case lt: // <
		var c, ok = compare(l, r)
		return c < 0 && ok
	case gt: // >
		var c, ok = compare(l, r)
		return c > 0 && ok
	case le: // <=
		var c, ok = compare(l, r)
		return c <= 0 && ok
	case ge: // >=
		var c, ok = compare(l, r)
		return c >= 0 && ok
	}
	var c, ok = compare(l, r)
	return c == 0 && ok
}

// InRange returns true if the given version is in the given range.
// nolint:cyclop
func InRange(l, rng string) bool {
	l = strings.ReplaceAll(l, " ", "")
	rng = strings.ReplaceAll(rng, " ", "")

	var or = false
	for _, rngOr := range strings.Split(rng, "||") {
		if len(rngOr) == 0 {
			continue
		}
		var and = true
		for _, r := range strings.Split(rngOr, ",") {
			if len(r) == 0 {
				continue
			}
			switch r[0] {
			case '<':
				r = r[1:]
				if len(r) == 0 {
					continue
				}
				switch r[0] {
				case '=':
					and = and && eval(l, le, r[1:])
				default:
					and = and && eval(l, lt, r)
				}
			case '>':
				r = r[1:]
				if len(r) == 0 {
					continue
				}
				switch r[0] {
				case '=':
					and = and && eval(l, ge, r[1:])
				default:
					and = and && eval(l, gt, r)
				}
			case '=':
				r = r[1:]
				if len(r) == 0 {
					continue
				}
				switch r[0] {
				case '=':
					and = and && eval(l, eq, r[1:])
				case '>':
					and = and && eval(l, ge, r[1:])
				case '<':
					and = and && eval(l, le, r[1:])
				default:
					and = and && eval(l, eq, r)
				}
			default:
				and = and && eval(l, eq, r)
			}
			if !and {
				break
			}
		}
		or = or || and
		if or {
			break
		}
	}
	return or
}

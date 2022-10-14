package genver

import "strings"

// InRange returns true if the given version is in the given range.
// nolint:cyclop
func InRange(v, rng string) bool {
	v = strings.ReplaceAll(v, " ", "")
	rng = strings.ReplaceAll(rng, " ", "")

	pv := parse(v)
	var or = false
	for _, rngOr := range strings.Split(rng, "||") {
		if len(rngOr) == 0 {
			continue
		}
		var and = true
		for _, w := range strings.Split(rngOr, ",") {
			if len(w) == 0 {
				continue
			}
			switch w[0] {
			case '<':
				w = w[1:]
				if len(w) == 0 {
					continue
				}
				switch w[0] {
				case '=':
					and = and && pv.Le(w[1:])
				default:
					and = and && pv.Lt(w)
				}
			case '>':
				w = w[1:]
				if len(w) == 0 {
					continue
				}
				switch w[0] {
				case '=':
					and = and && pv.Ge(w[1:])
				default:
					and = and && pv.Gt(w)
				}
			case '=':
				w = w[1:]
				if len(w) == 0 {
					continue
				}
				switch w[0] {
				case '=':
					and = and && pv.Eq(w[1:])
				case '>':
					and = and && pv.Ge(w[1:])
				case '<':
					and = and && pv.Le(w[1:])
				default:
					and = and && pv.Eq(w)
				}
			default:
				and = and && pv.Eq(w)
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

// IsUnboundedRange returns true if the given range is unbounded,
// the following cases are unbounded ranges.
//  - ">=0"
//  - "<6.3"
func IsUnboundedRange(rng string) bool {
	if rng != "" &&
		!strings.Contains(rng, "||") && !strings.Contains(rng, ",") {
		switch rng[0] {
		case '>', '<':
			return true
		}
	}
	return false
}

// IsLowerRangeOnly returns true if the given range has no upper range,
// the following cases are only lower ranges.
//  - ">=0"
//  - ">0"
func IsLowerRangeOnly(rng string) bool {
	if rng != "" &&
		!strings.Contains(rng, "||") && !strings.Contains(rng, ",") {
		switch rng[0] {
		case '>':
			return true
		}
	}
	return false
}

// IsUpperRangeOnly returns true if the given range has no lower range,
// the following cases are only upper ranges.
//  - "<6.3"
//  - "<=6.3"
func IsUpperRangeOnly(rng string) bool {
	if rng != "" &&
		!strings.Contains(rng, "||") && !strings.Contains(rng, ",") {
		switch rng[0] {
		case '<':
			return true
		}
	}
	return false
}

// IsEqualRangeOnly returns true if the given range has only equality range,
// the following cases are only equality ranges.
//  - "=6.3"
func IsEqualRangeOnly(rng string) bool {
	if rng != "" &&
		!strings.Contains(rng, "||") && !strings.Contains(rng, ",") {
		switch rng[0] {
		case '=':
			return true
		}
	}
	return false
}

// RestrictUnboundedRange returns bounded range restricted by the given boundary(w).
func RestrictUnboundedRange(w, ubrng string) (string, bool) {
	if ubrng == "" || w == "" {
		return "", false
	}

	var v = strings.TrimLeftFunc(ubrng, func(r rune) bool {
		switch r {
		default:
			return false
		case '>', '<', '=':
			return true
		}
	})
	var vop = strings.TrimSuffix(ubrng, v)

	var cr = Compare(v, w)
	switch cr {
	case 1: // v > w
		if vop[0] == '<' {
			return ">=" + w + "," + ubrng, true
		}
	case -1: // v < w
		if vop[0] == '>' {
			return ubrng + "," + "<=" + w, true
		}
	}
	return "", false
}

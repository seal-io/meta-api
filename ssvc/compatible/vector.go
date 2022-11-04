package compatible

// Vector holds the scoring functions of SSVC vector.
type Vector interface {
	// Priority returns the priority(in abbr.) of this SSVC vector.
	Priority() string

	// GetVersion returns the ssvc version of this SSVC vector.
	GetVersion() string
	// String returns the string format of this SSVC vector.
	String() string
	// IsZero returns true if this SSVC vector is empty.
	IsZero() bool
}

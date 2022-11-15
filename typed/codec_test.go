package typed

import (
	"bytes"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	type input struct {
		typ Type
		val any
	}
	var testCases = []struct {
		given    input
		expected []byte
	}{
		{
			given: input{
				typ: TypeFloat64,
				val: "0.2",
			},
			expected: []byte{63, 201, 153, 153, 153, 153, 153, 154},
		},
		{
			given: input{
				typ: TypeInt64,
				val: 1,
			},
			expected: []byte{0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			given: input{
				typ: TypeBoolean,
				val: func() *bool { var r bool; return &r }(),
			},
			expected: []byte{0},
		},
		{
			given: input{
				typ: TypeString,
				val: "xyz",
			},
			expected: []byte("xyz"),
		},
		{
			given: input{
				typ: TypeComplexJSON,
				val: map[string]string{
					"1": "1",
					"2": "2",
				},
			},
			expected: []byte(`{"1":"1","2":"2"}`),
		},
	}
	for i, c := range testCases {
		var actual, err = Encode(c.given.typ, c.given.val)
		if err != nil {
			t.Errorf("case %d failed: %v", i+1, err)
		} else if !bytes.Equal(c.expected, actual) {
			t.Errorf("case %d expected %v, but got %v",
				i+1, c.expected, actual)
		}
	}
}

func TestDecode(t *testing.T) {
	type input struct {
		typ      Type
		val      []byte
		receiver any
	}
	var testCases = []struct {
		given    input
		expected any
	}{
		{
			given: input{
				typ: TypeFloat64,
				val: []byte{63, 224, 0, 0, 0, 0, 0, 0},
			},
			expected: 0.5,
		},
		{
			given: input{
				typ: TypeInt64,
				val: []byte{0, 0, 0, 0, 0, 0, 0, 14},
			},
			expected: int64(14),
		},
		{
			given: input{
				typ: TypeBoolean,
				val: []byte{1},
			},
			expected: true,
		},
		{
			given: input{
				typ: TypeString,
				val: []byte(`yzx`),
			},
			expected: `yzx`,
		},
		{
			given: input{
				typ: TypeComplexJSON,
				val: []byte(`{"1":"1","2":"2","3":3}`),
			},
			expected: map[string]any{
				"1": "1",
				"2": "2",
				"3": float64(3),
			},
		},
		{
			given: input{
				typ: TypeComplexJSON,
				val: []byte(`["1","2"]`),
			},
			expected: []any{"1", "2"},
		},
	}
	for i, c := range testCases {
		var actual, err = Decode(c.given.typ, c.given.val)
		if err != nil {
			t.Errorf("case %d failed: %v", i+1, err)
		} else {
			if !reflect.DeepEqual(c.expected, actual) {
				t.Errorf("case %d expected %v, but got %v",
					i+1, c.expected, actual)
			}
		}
	}
}

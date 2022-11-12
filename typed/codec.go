package typed

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"unsafe"
)

// Type holds the type of feature.
type Type = string

const (
	TypeFloat64     Type = "float64"
	TypeInt64       Type = "int64"
	TypeBoolean     Type = "boolean"
	TypeString      Type = "string"
	TypeComplexJSON Type = "complex_json"
)

var byteOrder = binary.BigEndian

func IsValid(typ Type) bool {
	switch typ {
	case TypeFloat64, TypeInt64, TypeBoolean, TypeString, TypeComplexJSON:
		return true
	}
	return false
}

func Encode(typ Type, val any) ([]byte, error) {
	if !IsValid(typ) {
		return nil, errors.New("unknown type")
	}
	switch t := val.(type) {
	case []byte:
		return t, nil
	case bytes.Buffer:
		return t.Bytes(), nil
	case *bytes.Buffer:
		return t.Bytes(), nil
	}
	var b []byte
	switch typ {
	case TypeFloat64:
		b = make([]byte, 8)
		switch t := val.(type) {
		case float64:
			byteOrder.PutUint64(b[:], math.Float64bits(t))
		case *float64:
			byteOrder.PutUint64(b[:], math.Float64bits(*t))
		case float32:
			byteOrder.PutUint64(b[:], math.Float64bits(float64(t)))
		case *float32:
			byteOrder.PutUint64(b[:], math.Float64bits(float64(*t)))
		default:
			var vs = fmt.Sprintf("%v", val)
			var v, err = strconv.ParseFloat(vs, 64)
			if err != nil {
				return nil, fmt.Errorf("value cannot parse as float64: %w", err)
			}
			byteOrder.PutUint64(b[:], math.Float64bits(v))
		}
	case TypeInt64:
		b = make([]byte, 8)
		switch t := val.(type) {
		case int:
			byteOrder.PutUint64(b[:], uint64(t))
		case *int:
			byteOrder.PutUint64(b[:], uint64(*t))
		case int8:
			byteOrder.PutUint64(b[:], uint64(t))
		case *int8:
			byteOrder.PutUint64(b[:], uint64(*t))
		case int16:
			byteOrder.PutUint64(b[:], uint64(t))
		case *int16:
			byteOrder.PutUint64(b[:], uint64(*t))
		case int32:
			byteOrder.PutUint64(b[:], uint64(t))
		case *int32:
			byteOrder.PutUint64(b[:], uint64(*t))
		case int64:
			byteOrder.PutUint64(b[:], uint64(t))
		case *int64:
			byteOrder.PutUint64(b[:], uint64(*t))
		case uint:
			byteOrder.PutUint64(b[:], uint64(t))
		case *uint:
			byteOrder.PutUint64(b[:], uint64(*t))
		case uint8:
			byteOrder.PutUint64(b[:], uint64(t))
		case *uint8:
			byteOrder.PutUint64(b[:], uint64(*t))
		case uint32:
			byteOrder.PutUint64(b[:], uint64(t))
		case *uint32:
			byteOrder.PutUint64(b[:], uint64(*t))
		case uint64:
			byteOrder.PutUint64(b[:], t)
		case *uint64:
			byteOrder.PutUint64(b[:], *t)
		default:
			var vs = fmt.Sprintf("%v", val)
			var v, err = strconv.ParseInt(vs, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("value cannot parse as int64: %w", err)
			}
			byteOrder.PutUint64(b[:], uint64(v))
		}
	case TypeBoolean:
		switch t := val.(type) {
		case bool:
			if t {
				b = []byte{1}
			} else {
				b = []byte{0}
			}
		case *bool:
			if *t {
				b = []byte{1}
			} else {
				b = []byte{0}
			}
		default:
			var vv = reflect.ValueOf(val)
			if vv.Kind() == reflect.Pointer {
				vv = vv.Elem()
			}
			var vs = fmt.Sprintf("%v", vv)
			var v, err = strconv.ParseBool(vs)
			if err != nil {
				return nil, fmt.Errorf("value cannot parse as boolean: %w", err)
			}
			if v {
				b = []byte{1}
			} else {
				b = []byte{0}
			}
		}
	case TypeString:
		switch t := val.(type) {
		case string:
			b = s2b(t)
		case *string:
			b = s2b(*t)
		default:
			var vv = reflect.ValueOf(val)
			if vv.Kind() == reflect.Pointer {
				vv = vv.Elem()
			}
			var v = fmt.Sprintf("%v", vv.Interface())
			b = s2b(v)
		}
	case TypeComplexJSON:
		var err error
		b, err = json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("value cannot parse as complex json: %w", err)
		}
	}
	return b, nil
}

func Decode(typ Type, b []byte, r any) error {
	if !IsValid(typ) {
		return errors.New("unknown type")
	}
	var rv = reflect.ValueOf(r)
	var rvk = rv.Kind()
	if rvk != reflect.Pointer || rv.IsNil() {
		return errors.New("invalid receiver: not a pointer")
	}
	rv = rv.Elem()
	switch typ {
	case TypeFloat64:
		if rv.Kind() != reflect.Float64 {
			return errors.New("invalid receiver: not a float64 pointer")
		}
		rv.Set(reflect.ValueOf(math.Float64frombits(byteOrder.Uint64(b))))
	case TypeInt64:
		if rv.Kind() != reflect.Int64 {
			return errors.New("invalid receiver: not a int64 pointer")
		}
		rv.Set(reflect.ValueOf(int64(byteOrder.Uint64(b))))
	case TypeBoolean:
		if rv.Kind() != reflect.Bool {
			return errors.New("invalid receiver: not a boolean pointer")
		}
		rv.Set(reflect.ValueOf(bytes.Equal(b, []byte{1})))
	case TypeString:
		if rv.Kind() != reflect.String {
			return errors.New("invalid receiver: not a string pointer")
		}
		rv.Set(reflect.ValueOf(b2s(b)))
	case TypeComplexJSON:
		return json.Unmarshal(b, r)
	}
	return nil
}

func s2b(s string) (bytes []byte) {
	var slice = (*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	var str = (*reflect.StringHeader)(unsafe.Pointer(&s))
	slice.Len = str.Len
	slice.Cap = str.Len
	slice.Data = str.Data
	return bytes
}

func b2s(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

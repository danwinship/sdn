package ranges

import (
	"fmt"
	"math"
	"net"
	"reflect"
	"testing"
)

func TestNewFixedInt(t *testing.T) {
	for _, tc := range []struct {
		val    uint64
		bitlen int
		mInt   *fixedInt
		fail   bool
	}{
		{
			val:    0,
			bitlen: 16,
			mInt:   &fixedInt{high: 0, low: 0, bitlen: 16},
		},
		{
			val:    12345,
			bitlen: 64,
			mInt:   &fixedInt{high: 0, low: 12345, bitlen: 64},
		},
		{
			val:    0,
			bitlen: 128,
			mInt:   &fixedInt{high: 0, low: 0, bitlen: 128},
		},
		{
			val:    math.MaxUint64,
			bitlen: 128,
			mInt:   &fixedInt{high: 0, low: math.MaxUint64, bitlen: 128},
		},
		{
			val:    0,
			bitlen: 1,
			fail:   true,
		},
	} {
		t.Run(fmt.Sprintf("%d/%d", tc.val, tc.bitlen), func(t *testing.T) {
			defer func() {
				if msg := recover(); msg != nil {
					if !tc.fail {
						t.Errorf("unexpected panic: %s", msg)
					}
				} else if tc.fail {
					t.Errorf("unexpected failure to panic")
				}
			}()
			mInt := newFixedInt(tc.val, tc.bitlen)
			if !reflect.DeepEqual(mInt, tc.mInt) {
				t.Errorf("expected %s, got %s", tc.mInt, mInt)
			}
		})
	}
}

func TestNewFixedIntFromBytes(t *testing.T) {
	for _, tc := range []struct {
		bytes []byte
		mInt  *fixedInt
		fail  bool
	}{
		{
			bytes: []byte{1, 2},
			mInt:  &fixedInt{high: 0, low: 0x0102, bitlen: 16},
		},
		{
			bytes: []byte{1, 2, 3, 4},
			mInt:  &fixedInt{high: 0, low: 0x01020304, bitlen: 32},
		},
		{
			bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			mInt:  &fixedInt{high: 0, low: 0x0102030405060708, bitlen: 64},
		},
		{
			bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			mInt: &fixedInt{
				high:   0x0102030405060708,
				low:    0x090a0b0c0d0e0f10,
				bitlen: 128,
			},
		},
		{
			bytes: []byte{},
			fail:  true,
		},
		{
			bytes: []byte{1, 2, 3},
			fail:  true,
		},
	} {
		t.Run(fmt.Sprintf("%#v", tc.bytes), func(t *testing.T) {
			defer func() {
				if msg := recover(); msg != nil {
					if !tc.fail {
						t.Errorf("unexpected panic: %s", msg)
					}
				} else if tc.fail {
					t.Errorf("unexpected failure to panic")
				}
			}()
			mInt := newFixedIntFromBytes(tc.bytes)
			if !reflect.DeepEqual(mInt, tc.mInt) {
				t.Errorf("expected %s, got %s", tc.mInt, mInt)
			}
			roundTrip := mInt.toBytes()
			if !reflect.DeepEqual(roundTrip, tc.bytes) {
				t.Errorf("round trip failure: expected %#v, got %#v", tc.bytes, roundTrip)
			}
		})
	}
}

func ipFromCIDR(cidr string) []byte {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("bad cidr: %v", err))
	}
	return ip
}

func maskFromCIDR(cidr string) []byte {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("bad cidr: %v", err))
	}
	return ipNet.Mask
}

func TestNewFixedIntFromIP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ip          net.IP
		mInt        *fixedInt
		noRoundTrip bool
		fail        bool
	}{
		{
			name: "10.0.0.1",
			ip:   net.ParseIP("10.0.0.1"),
			mInt: &fixedInt{high: 0, low: 0x0a000001, bitlen: 32},

			// bytes could be 4 or 16 bytes, but roundTrip will be 4
			noRoundTrip: true,
		},
		{
			name: "10.0.0.1 .to4",
			ip:   net.ParseIP("10.0.0.1").To4(),
			mInt: &fixedInt{high: 0, low: 0x0a000001, bitlen: 32},
		},
		{
			name: "10.0.0.1 .to16",
			ip:   net.ParseIP("10.0.0.1").To16(),
			mInt: &fixedInt{high: 0, low: 0x0a000001, bitlen: 32},

			// bytes is 16 bytes, but roundTrip will be 4
			noRoundTrip: true,
		},
		{
			name: "fe80::abcd",
			ip:   net.ParseIP("fe80::abcd"),
			mInt: &fixedInt{
				high:   0xfe80000000000000,
				low:    0x000000000000abcd,
				bitlen: 128,
			},
		},
		{
			name: "10.128.0.0/14 ip",
			ip:   ipFromCIDR("10.128.0.0/14"),
			mInt: &fixedInt{high: 0, low: 0x0a800000, bitlen: 32},

			// bytes could be 4 or 16 bytes, but roundTrip will be 4
			noRoundTrip: true,
		},
		{
			name: "10.128.0.0/14 mask",
			ip:   maskFromCIDR("10.128.0.0/14"),
			mInt: &fixedInt{high: 0, low: 0xfffc0000, bitlen: 32},

			// IPv4 mask is always 4 bytes; there is no 16-byte representation
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if msg := recover(); msg != nil {
					if !tc.fail {
						t.Errorf("unexpected panic: %s", msg)
					}
				} else if tc.fail {
					t.Errorf("unexpected failure to panic")
				}
			}()
			mInt := newFixedIntFromIP(tc.ip)
			if !reflect.DeepEqual(mInt, tc.mInt) {
				t.Errorf("expected %s, got %s", tc.mInt, mInt)
			}
			if !tc.noRoundTrip {
				roundTrip := mInt.toBytes()
				if !reflect.DeepEqual(roundTrip, []byte(tc.ip)) {
					t.Errorf("round trip failure: expected %#v, got %#v", []byte(tc.ip), roundTrip)
				}
			}
		})
	}
}

func TestNewFixedIntMask(t *testing.T) {
	for _, tc := range []struct {
		ones   int
		bitlen int
		mInt   *fixedInt
		fail   bool
	}{
		{
			ones:   0,
			bitlen: 16,
			mInt:   &fixedInt{high: 0, low: 0, bitlen: 16},
		},
		{
			ones:   9,
			bitlen: 16,
			mInt:   &fixedInt{high: 0, low: 0xff80, bitlen: 16},
		},
		{
			ones:   9,
			bitlen: 32,
			mInt:   &fixedInt{high: 0, low: 0xff800000, bitlen: 32},
		},
		{
			ones:   0,
			bitlen: 64,
			mInt:   &fixedInt{high: 0, low: 0, bitlen: 64},
		},
		{
			ones:   1,
			bitlen: 64,
			mInt:   &fixedInt{high: 0, low: 0x8000000000000000, bitlen: 64},
		},
		{
			ones:   63,
			bitlen: 64,
			mInt:   &fixedInt{high: 0, low: 0xfffffffffffffffe, bitlen: 64},
		},
		{
			ones:   64,
			bitlen: 64,
			mInt:   &fixedInt{high: 0, low: 0xffffffffffffffff, bitlen: 64},
		},
		{
			ones:   0,
			bitlen: 128,
			mInt:   &fixedInt{high: 0, low: 0, bitlen: 128},
		},
		{
			ones:   9,
			bitlen: 128,
			mInt: &fixedInt{
				high:   0xff80000000000000,
				low:    0,
				bitlen: 128,
			},
		},
		{
			ones:   64,
			bitlen: 128,
			mInt: &fixedInt{
				high:   0xffffffffffffffff,
				low:    0,
				bitlen: 128,
			},
		},
		{
			ones:   99,
			bitlen: 128,
			mInt: &fixedInt{
				high:   0xffffffffffffffff,
				low:    0xffffffffe0000000,
				bitlen: 128,
			},
		},
		{
			ones:   128,
			bitlen: 128,
			mInt: &fixedInt{
				high:   0xffffffffffffffff,
				low:    0xffffffffffffffff,
				bitlen: 128,
			},
		},
		{
			ones:   9,
			bitlen: 9,
			fail:   true,
		},
		{
			ones:   19,
			bitlen: 16,
			fail:   true,
		},
	} {
		t.Run(fmt.Sprintf("%d/%d", tc.ones, tc.bitlen), func(t *testing.T) {
			defer func() {
				if msg := recover(); msg != nil {
					if !tc.fail {
						t.Errorf("unexpected panic: %s", msg)
					}
				} else if tc.fail {
					t.Errorf("unexpected failure to panic")
				}
			}()
			mInt := newFixedIntMask(tc.ones, tc.bitlen)
			if !reflect.DeepEqual(mInt, tc.mInt) {
				t.Errorf("expected %s, got %s", tc.mInt, mInt)
			}
		})
	}
}

func TestFixedInt_plusOne_minusOne(t *testing.T) {
	for _, tc := range []struct {
		val     *fixedInt
		plusOne *fixedInt
		plusTwo *fixedInt
	}{
		{
			val:     &fixedInt{high: 0, low: 0, bitlen: 16},
			plusOne: &fixedInt{high: 0, low: 1, bitlen: 16},
			plusTwo: &fixedInt{high: 0, low: 2, bitlen: 16},
		},
		{
			val:     &fixedInt{high: 0, low: 0x0ff, bitlen: 32},
			plusOne: &fixedInt{high: 0, low: 0x100, bitlen: 32},
			plusTwo: &fixedInt{high: 0, low: 0x101, bitlen: 32},
		},
		{
			val:     &fixedInt{high: 0, low: math.MaxUint64 - 2, bitlen: 64},
			plusOne: &fixedInt{high: 0, low: math.MaxUint64 - 1, bitlen: 64},
			plusTwo: &fixedInt{high: 0, low: math.MaxUint64, bitlen: 64},
		},
		{
			val:     &fixedInt{high: 0, low: math.MaxUint64 - 1, bitlen: 128},
			plusOne: &fixedInt{high: 0, low: math.MaxUint64, bitlen: 128},
			plusTwo: &fixedInt{high: 1, low: 0, bitlen: 128},
		},
		{
			val:     &fixedInt{high: 1, low: 0, bitlen: 128},
			plusOne: &fixedInt{high: 1, low: 1, bitlen: 128},
			plusTwo: &fixedInt{high: 1, low: 2, bitlen: 128},
		},
		// Note that plusOne() and minusOne() are explicitly undefined on overflow
	} {
		t.Run(fmt.Sprintf("%s", tc.val), func(t *testing.T) {
			p1 := tc.val.plusOne()
			p2 := p1.plusOne()
			m1 := p2.minusOne()
			m2 := m1.minusOne()
			if !reflect.DeepEqual(p1, tc.plusOne) {
				t.Errorf("+1 expected %s, got %s", tc.plusOne, p1)
			}
			if !reflect.DeepEqual(p2, tc.plusTwo) {
				t.Errorf("+2 expected %s, got %s", tc.plusTwo, p2)
			}
			if !reflect.DeepEqual(m1, tc.plusOne) {
				t.Errorf("-1 expected %s, got %s", tc.plusOne, m1)
			}
			if !reflect.DeepEqual(m2, tc.val) {
				t.Errorf("-2 expected %s, got %s", tc.val, m2)
			}
		})
	}
}

func TestFixedInt_not(t *testing.T) {
	for _, tc := range []struct {
		val *fixedInt
		not *fixedInt
	}{
		{
			val: &fixedInt{high: 0, low: 0, bitlen: 16},
			not: &fixedInt{high: 0, low: 0xffff, bitlen: 16},
		},
		{
			val: &fixedInt{high: 0, low: 0x0000ffff, bitlen: 32},
			not: &fixedInt{high: 0, low: 0xffff0000, bitlen: 32},
		},
		{
			val: &fixedInt{high: 0, low: 0x12345678, bitlen: 64},
			not: &fixedInt{high: 0, low: 0xffffffffedcba987, bitlen: 64},
		},
		{
			val: &fixedInt{high: 0, low: 0, bitlen: 128},
			not: &fixedInt{
				high:   0xffffffffffffffff,
				low:    0xffffffffffffffff,
				bitlen: 128,
			},
		},
		{
			val: &fixedInt{high: 0xffff, low: 0xabcd, bitlen: 128},
			not: &fixedInt{
				high:   0xffffffffffff0000,
				low:    0xffffffffffff5432,
				bitlen: 128,
			},
		},
	} {
		t.Run(fmt.Sprintf("%s", tc.val), func(t *testing.T) {
			not := tc.val.not()
			if !reflect.DeepEqual(not, tc.not) {
				t.Errorf("expected %s, got %s", tc.not, not)
			}
		})
	}
}

func TestFixedInt_or(t *testing.T) {
	for _, tc := range []struct {
		x    *fixedInt
		y    *fixedInt
		xory *fixedInt
	}{
		{
			x:    &fixedInt{high: 0, low: 0x9090, bitlen: 16},
			y:    &fixedInt{high: 0, low: 0x1234, bitlen: 16},
			xory: &fixedInt{high: 0, low: 0x92b4, bitlen: 16},
		},
		{
			x:    &fixedInt{high: 0, low: 0xabcd1234, bitlen: 32},
			y:    &fixedInt{high: 0, low: 0, bitlen: 32},
			xory: &fixedInt{high: 0, low: 0xabcd1234, bitlen: 32},
		},
		{
			x:    &fixedInt{high: 0x1111, low: 0x6666, bitlen: 128},
			y:    &fixedInt{high: 0x2222, low: 0x9999, bitlen: 128},
			xory: &fixedInt{high: 0x3333, low: 0xffff, bitlen: 128},
		},
	} {
		t.Run(fmt.Sprintf("%s^%s", tc.x, tc.y), func(t *testing.T) {
			xory := tc.x.or(tc.y)
			if !reflect.DeepEqual(xory, tc.xory) {
				t.Errorf("expected %s, got %s", tc.xory, xory)
			}
		})
	}
}

func TestFixedInt_lastForMask(t *testing.T) {
	for _, tc := range []struct {
		x    *fixedInt
		mask *fixedInt
		last *fixedInt
	}{
		{
			x:    newFixedIntFromBytes(net.ParseIP("192.168.0.0")),
			mask: newFixedIntMask(17, 32),
			last: newFixedIntFromBytes(net.ParseIP("192.168.127.255")),
		},
		{
			x:    newFixedIntFromBytes(net.ParseIP("192.168.1.5")),
			mask: newFixedIntMask(17, 32),
			last: newFixedIntFromBytes(net.ParseIP("192.168.127.255")),
		},
		{
			x:    newFixedIntFromBytes(net.ParseIP("fe80::1234")),
			mask: newFixedIntMask(17, 128),
			last: newFixedIntFromBytes(net.ParseIP("fe80:7fff:ffff:ffff:ffff:ffff:ffff:ffff")),
		},
		{
			x:    newFixedIntFromBytes(net.ParseIP("fe80::1234")),
			mask: newFixedIntMask(107, 128),
			last: newFixedIntFromBytes(net.ParseIP("fe80::1f:ffff")),
		},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.x, tc.mask), func(t *testing.T) {
			last := tc.x.lastForMask(tc.mask)
			if !reflect.DeepEqual(last, tc.last) {
				t.Errorf("expected %s, got %s", tc.last, last)
			}
		})
	}
}

func TestFixedInt_leadingZeros_trailingZeros(t *testing.T) {
	for _, tc := range []struct {
		val      *fixedInt
		leading  int
		trailing int
	}{
		{
			val:      &fixedInt{high: 0, low: 0, bitlen: 16},
			leading:  16,
			trailing: 16,
		},
		{
			val:      &fixedInt{high: 0, low: 0x1230, bitlen: 16},
			leading:  3,
			trailing: 4,
		},
		{
			val:      &fixedInt{high: 0, low: math.MaxUint16, bitlen: 16},
			leading:  0,
			trailing: 0,
		},
		{
			val:      &fixedInt{high: 0, low: 0x1230, bitlen: 32},
			leading:  19,
			trailing: 4,
		},
		{
			val:      &fixedInt{high: 0, low: 0, bitlen: 32},
			leading:  32,
			trailing: 32,
		},
		{
			val:      &fixedInt{high: 0, low: math.MaxUint32, bitlen: 32},
			leading:  0,
			trailing: 0,
		},
		{
			val:      &fixedInt{high: 0, low: 0, bitlen: 64},
			leading:  64,
			trailing: 64,
		},
		{
			val:      &fixedInt{high: 0, low: 0x0000123456780000, bitlen: 64},
			leading:  19,
			trailing: 19,
		},
		{
			val:      &fixedInt{high: 0, low: math.MaxUint64, bitlen: 64},
			leading:  0,
			trailing: 0,
		},
		{
			val:      &fixedInt{high: math.MaxUint64, low: math.MaxUint64, bitlen: 128},
			leading:  0,
			trailing: 0,
		},
		{
			val:      &fixedInt{high: math.MaxUint64, low: 0, bitlen: 128},
			leading:  0,
			trailing: 64,
		},
		{
			val:      &fixedInt{high: 1, low: 0, bitlen: 128},
			leading:  63,
			trailing: 64,
		},
		{
			val:      &fixedInt{high: 0, low: 0x4000000000000000, bitlen: 128},
			leading:  65,
			trailing: 62,
		},
	} {
		t.Run(fmt.Sprintf("%s", tc.val), func(t *testing.T) {
			leading := tc.val.leadingZeroBits()
			trailing := tc.val.trailingZeroBits()
			if leading != tc.leading || trailing != tc.trailing {
				t.Errorf("expected %d/%d, got %d/%d", tc.leading, tc.trailing, leading, trailing)
			}
		})
	}
}

func TestFixedInt_cmp(t *testing.T) {
	for _, tc := range []struct {
		x   *fixedInt
		y   *fixedInt
		cmp int
	}{
		{
			x:   &fixedInt{high: 0, low: 0, bitlen: 16},
			y:   &fixedInt{high: 0, low: 1, bitlen: 16},
			cmp: -1,
		},
		{
			x:   &fixedInt{high: 0, low: 1, bitlen: 16},
			y:   &fixedInt{high: 0, low: 1, bitlen: 16},
			cmp: 0,
		},
		{
			x:   &fixedInt{high: 0, low: 2, bitlen: 16},
			y:   &fixedInt{high: 0, low: 1, bitlen: 16},
			cmp: 1,
		},
		{
			x:   &fixedInt{high: 0, low: 0xffff0000, bitlen: 32},
			y:   &fixedInt{high: 0, low: 0x0000ffff, bitlen: 32},
			cmp: 1,
		},
		{
			x:   &fixedInt{high: 0, low: 0xffff0000, bitlen: 128},
			y:   &fixedInt{high: 1, low: 0x0000ffff, bitlen: 128},
			cmp: -1,
		},
		{
			x:   &fixedInt{high: 12345, low: 67890, bitlen: 128},
			y:   &fixedInt{high: 12345, low: 67890, bitlen: 128},
			cmp: 0,
		},
	} {
		t.Run(fmt.Sprintf("%s <=> %s", tc.x, tc.y), func(t *testing.T) {
			switch tc.cmp {
			case -1:
				if !tc.x.lessThan(tc.y) || !tc.x.lessOrEqual(tc.y) || tc.x.equal(tc.y) || tc.x.greaterOrEqual(tc.y) || tc.x.greaterThan(tc.y) {
					t.Errorf("bad comparisons: < %t, <= %t, == %t, >= %t, > %t",
						tc.x.lessThan(tc.y), tc.x.lessOrEqual(tc.y),
						tc.x.equal(tc.y),
						tc.x.greaterOrEqual(tc.y), tc.x.greaterThan(tc.y))
				}
			case 0:
				if tc.x.lessThan(tc.y) || !tc.x.lessOrEqual(tc.y) || !tc.x.equal(tc.y) || !tc.x.greaterOrEqual(tc.y) || tc.x.greaterThan(tc.y) {
					t.Errorf("bad comparisons: < %t, <= %t, == %t, >= %t, > %t",
						tc.x.lessThan(tc.y), tc.x.lessOrEqual(tc.y),
						tc.x.equal(tc.y),
						tc.x.greaterOrEqual(tc.y), tc.x.greaterThan(tc.y))
				}
			case 1:
				if tc.x.lessThan(tc.y) || tc.x.lessOrEqual(tc.y) || tc.x.equal(tc.y) || !tc.x.greaterOrEqual(tc.y) || !tc.x.greaterThan(tc.y) {
					t.Errorf("bad comparisons: < %t, <= %t, == %t, >= %t, > %t",
						tc.x.lessThan(tc.y), tc.x.lessOrEqual(tc.y),
						tc.x.equal(tc.y),
						tc.x.greaterOrEqual(tc.y), tc.x.greaterThan(tc.y))
				}
			}
		})
	}
}

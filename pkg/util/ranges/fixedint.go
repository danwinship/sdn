package ranges

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"net"
)

// fixedInt is like big.Int except smaller and fixed-length. We can't just use regular int
// types here because we'd need a "uint128" for IPv6 support, and we can't use big.Int
// because it's not fixed-length, so operations that depend on the length of the value
// (eg, leadingZeroBits()) would not be well-defined.
type fixedInt struct {
	high   uint64
	low    uint64
	bitlen int
}

// newFixedInt creates a new fixedInt from val. bitlen must be 16, 32, 64, or 128.
func newFixedInt(val uint64, bitlen int) *fixedInt {
	if bitlen != 128 && bitlen != 64 && bitlen != 32 && bitlen != 16 {
		panic("bad bit length")
	}
	return &fixedInt{
		low:    val,
		bitlen: bitlen,
	}
}

// newFixedIntFromBytes creates a new fixedInt from the big-endian value in bytes (which
// must have a valid length for a fixedInt).
func newFixedIntFromBytes(bytes []byte) *fixedInt {
	switch len(bytes) {
	case 16:
		return &fixedInt{
			high:   binary.BigEndian.Uint64(bytes[:8]),
			low:    binary.BigEndian.Uint64(bytes[8:]),
			bitlen: 128,
		}
	case 8:
		return &fixedInt{
			low:    binary.BigEndian.Uint64(bytes[:8]),
			bitlen: 64,
		}
	case 4:
		return &fixedInt{
			low:    uint64(binary.BigEndian.Uint32(bytes)),
			bitlen: 32,
		}
	case 2:
		return &fixedInt{
			low:    uint64(binary.BigEndian.Uint16(bytes)),
			bitlen: 16,
		}
	default:
		panic("bad bit length")
	}
}

// newFixedIntFromIP creates a new fixedInt from the given IP address. (Unlike with
// newFixedIntFromBytes(), IPv4 addresses will always be turned into 32-bit fixedInts,
// even if they are represented as 16 bytes.)
func newFixedIntFromIP(ip net.IP) *fixedInt {
	bytes := []byte(ip)
	to4 := ip.To4()
	if to4 != nil {
		bytes = []byte(to4)
	}
	return newFixedIntFromBytes(bytes)
}

// newFixedIntMask creates a new fixedInt representing a mask of a given size.
// (ie, ones 1 bits followed by (bitlen-ones) 0 bits).
func newFixedIntMask(ones, bitlen int) *fixedInt {
	if bitlen != 128 && bitlen != 64 && bitlen != 32 && bitlen != 16 {
		panic("bad bit length")
	}
	if ones > bitlen || ones < 0 {
		panic("bad mask length")
	}

	switch {
	case bitlen == 128 && ones <= 64:
		return &fixedInt{
			high:   math.MaxUint64 << (64 - ones),
			low:    0,
			bitlen: 128,
		}
	case bitlen == 128 /* && ones > 64 */ :
		return &fixedInt{
			high:   math.MaxUint64,
			low:    math.MaxUint64 << (128 - ones),
			bitlen: 128,
		}
	default:
		// eg for newFixedIntMask(3, 8), ^(1<<(8-3) - 1) == ^(1<<5 - 1) ==
		// ^(00100000 - 1) == ^00011111 == 11100000. Overflow is well-defined in
		// golang so this works even for bitlen=64 ones=0.
		return &fixedInt{
			low:    ^(1<<(bitlen-ones) - 1) & ^(math.MaxUint64 << bitlen),
			bitlen: bitlen,
		}
	}
}

// toBytes converts a fixedInt to a big-endian []byte representation
func (x *fixedInt) toBytes() []byte {
	bytes := make([]byte, x.bitlen/8)

	switch len(bytes) {
	case 16:
		binary.BigEndian.PutUint64(bytes, x.high)
		binary.BigEndian.PutUint64(bytes[8:], x.low)
	case 8:
		binary.BigEndian.PutUint64(bytes, x.low)
	case 4:
		binary.BigEndian.PutUint32(bytes, uint32(x.low))
	case 2:
		binary.BigEndian.PutUint16(bytes, uint16(x.low))
	default:
		panic("not reached")
	}
	return bytes
}

// low64 returns the low 64 bytes of x
func (x *fixedInt) low64() uint64 {
	return x.low
}

// low32 returns the low 32 bytes of x
func (x *fixedInt) low32() uint32 {
	return uint32(x.low)
}

// low16 returns the low 16 bytes of x
func (x *fixedInt) low16() uint16 {
	return uint16(x.low)
}

// String converts a fixedInt to some string representation. Use this only for debugging
// purposes. (Currently 128-bit and 32-bit values are converted to IPs, and 64-bit and
// 16-bit values are converted as integers.)
func (x *fixedInt) String() string {
	if x.bitlen == 128 || x.bitlen == 32 {
		return net.IP(x.toBytes()).String()
	} else {
		return fmt.Sprintf("%d", x.low)
	}
}

// x.plusOne() returns x+1. Assumes overflow will not occur.
func (x *fixedInt) plusOne() *fixedInt {
	if x.low == math.MaxUint64 {
		return &fixedInt{high: x.high + 1, low: 0, bitlen: x.bitlen}
	} else {
		return &fixedInt{high: x.high, low: x.low + 1, bitlen: x.bitlen}
	}
}

// x.minusOne() returns x-1. Assumes underflow will not occur.
func (x *fixedInt) minusOne() *fixedInt {
	if x.low == 0 {
		return &fixedInt{high: x.high - 1, low: math.MaxUint64, bitlen: x.bitlen}
	} else {
		return &fixedInt{high: x.high, low: x.low - 1, bitlen: x.bitlen}
	}
}

// x.sub(y) returns x-y. Assumes underflow will not occur.
func (x *fixedInt) sub(y *fixedInt) *fixedInt {
	ret := &fixedInt{high: x.high - y.high, low: x.low - y.low, bitlen: x.bitlen}
	if y.low > x.low {
		ret.high--
	}
	return ret
}

// x.not() returns ^x.
func (x *fixedInt) not() *fixedInt {
	switch x.bitlen {
	case 128:
		return &fixedInt{high: ^x.high, low: ^x.low, bitlen: x.bitlen}
	case 64:
		return &fixedInt{high: 0, low: ^x.low, bitlen: x.bitlen}
	case 32:
		return &fixedInt{high: 0, low: x.low ^ math.MaxUint32, bitlen: x.bitlen}
	case 16:
		return &fixedInt{high: 0, low: x.low ^ math.MaxUint16, bitlen: x.bitlen}
	default:
		panic("bad bit length")
	}
}

// x.or(y) returns x^y
func (x *fixedInt) or(y *fixedInt) *fixedInt {
	return &fixedInt{low: x.low | y.low, high: x.high | y.high, bitlen: x.bitlen}
}

// x.lastForMask(m) returns the last value in the range x/m
func (x *fixedInt) lastForMask(mask *fixedInt) *fixedInt {
	// eg, if x is 192.168.0.0 = 0xc0a80000 and mask is 0xffffff00, then mask.not() is
	// 0x000000ff, and so we return 0xc0a800ff = 192.168.0.255
	return x.or(mask.not())
}

// leadingZeroBits returns the number of leading "0" bits in x
func (x *fixedInt) leadingZeroBits() int {
	if x.high != 0 {
		return bits.LeadingZeros64(x.high)
	} else {
		return bits.LeadingZeros64(x.low) - (64 - x.bitlen)
	}
}

// trailingZeroBits returns the number of trailing "0" bits in x
func (x *fixedInt) trailingZeroBits() int {
	if x.low != 0 {
		return bits.TrailingZeros64(x.low)
	} else if x.high != 0 {
		return bits.TrailingZeros64(x.high) + 64
	} else {
		return x.bitlen
	}
}

// x.lessThan(y) returns whether x is less than y
func (x *fixedInt) lessThan(y *fixedInt) bool {
	return (x.high < y.high) || (x.high == y.high && x.low < y.low)
}

// x.lessOrEqual(y) returns whether x is less than or equal to y
func (x *fixedInt) lessOrEqual(y *fixedInt) bool {
	return x.lessThan(y) || x.equal(y)
}

// x.equal(y) returns whether x is equal to y
func (x *fixedInt) equal(y *fixedInt) bool {
	return (x.high == y.high) && (x.low == y.low)
}

// x.greaterThan(y) returns whether x is greater than y
func (x *fixedInt) greaterThan(y *fixedInt) bool {
	return (x.high > y.high) || (x.high == y.high && x.low > y.low)
}

// x.greaterOrEqual(y) returns whether x is greater than or equal to y
func (x *fixedInt) greaterOrEqual(y *fixedInt) bool {
	return x.greaterThan(y) || x.equal(y)
}

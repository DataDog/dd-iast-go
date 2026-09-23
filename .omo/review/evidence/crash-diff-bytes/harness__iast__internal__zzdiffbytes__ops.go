// Package zzdiffbytes is a review-only differential harness. Every direct
// call in this file is woven by orchestrion; ops_native.go drives the same
// operations through method values and function values, which are not.
package zzdiffbytes

import (
	"bytes"
	"io"
	"strings"
	"unsafe"
)

type BufHolder struct{ B bytes.Buffer }
type BldHolder struct{ B strings.Builder }

// Op is one writer operation.
type Op struct {
	Kind int
	Ptr  bool
	S    string
	Bs   []byte
	N    int
	R    rune
	C    byte
}

// Res captures every Go-visible result of an operation.
type Res struct {
	N     int
	N64   int64
	Err   string
	S     string
	HasS  bool
	Bs    []byte
	HasBs bool
	BsOff int
	R     rune
	C     byte
	Panic string
	Out   []byte // WriteTo sink content
}

const (
	OpWrite = iota
	OpWriteString
	OpWriteByte
	OpWriteRune
	OpGrow
	OpReset
	OpTruncate
	OpString
	OpRead
	OpNext
	OpReadByte
	OpReadRune
	OpUnreadByte
	OpUnreadRune
	OpReadBytes
	OpReadString
	OpReadFrom
	OpWriteTo
	OpBytes
	OpBytesMutate
	OpAvailAppendWrite
	OpPeek
	OpPeekMutate
	OpSelfWriteBytes
	OpSelfWriteString
	OpLenCap
	OpCopyWrite
	OpNilRecv
	OpCount
)

type bufInternal struct {
	buf      []byte
	off      int
	lastRead int8
}

// BufBase returns the internal backing slice without calling hooked methods.
func BufBase(b *bytes.Buffer) []byte { return (*bufInternal)(unsafe.Pointer(b)).buf }

// BufState encodes the full internal state of a Buffer.
func BufState(dst []byte, b *bytes.Buffer) []byte {
	in := (*bufInternal)(unsafe.Pointer(b))
	dst = appendInt(dst, int64(len(in.buf)))
	dst = appendInt(dst, int64(cap(in.buf)))
	dst = appendInt(dst, int64(in.off))
	dst = appendInt(dst, int64(in.lastRead))
	dst = appendInt(dst, int64(b.Len()))
	dst = appendInt(dst, int64(b.Cap()))
	dst = appendInt(dst, int64(b.Available()))
	return appendBytes(dst, in.buf)
}

type bldInternal struct {
	addr *strings.Builder
	buf  []byte
}

// BldState encodes the full internal state of a Builder.
func BldState(dst []byte, b *strings.Builder) []byte {
	in := (*bldInternal)(unsafe.Pointer(b))
	self := int64(0)
	if in.addr == b {
		self = 1
	} else if in.addr != nil {
		self = 2
	}
	dst = appendInt(dst, self)
	dst = appendInt(dst, int64(len(in.buf)))
	dst = appendInt(dst, int64(cap(in.buf)))
	dst = appendInt(dst, int64(b.Len()))
	dst = appendInt(dst, int64(b.Cap()))
	return appendBytes(dst, in.buf)
}

func appendInt(dst []byte, v int64) []byte {
	u := uint64(v)
	for i := 0; i < 8; i++ {
		dst = append(dst, byte(u>>(8*i)))
	}
	return dst
}

func appendBytes(dst, v []byte) []byte {
	if v == nil {
		dst = append(dst, 0)
	} else {
		dst = append(dst, 1)
	}
	dst = appendInt(dst, int64(len(v)))
	dst = appendInt(dst, int64(cap(v)))
	return append(dst, v...)
}

func appendString(dst []byte, v string) []byte {
	dst = appendInt(dst, int64(len(v)))
	return append(dst, v...)
}

// Enc encodes a result for comparison and digest.
func (r *Res) Enc(dst []byte) []byte {
	dst = appendInt(dst, int64(r.N))
	dst = appendInt(dst, r.N64)
	dst = appendString(dst, r.Err)
	dst = appendString(dst, r.S)
	if r.HasBs {
		dst = appendBytes(dst, r.Bs)
		dst = appendInt(dst, int64(r.BsOff))
	}
	dst = appendInt(dst, int64(r.R))
	dst = append(dst, r.C)
	dst = appendString(dst, r.Panic)
	return appendBytes(dst, r.Out)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// AliasOff returns the offset of v inside base's allocation, or -1.
func AliasOff(v, base []byte) int {
	if cap(v) == 0 || cap(base) == 0 {
		return -1
	}
	p := uintptr(unsafe.Pointer(unsafe.SliceData(v)))
	b := uintptr(unsafe.Pointer(unsafe.SliceData(base)))
	if p < b || p >= b+uintptr(cap(base)) {
		return -1
	}
	return int(p - b)
}

func recoverTo(r *Res) {
	if p := recover(); p != nil {
		switch v := p.(type) {
		case error:
			r.Panic = "E:" + v.Error()
		case string:
			r.Panic = "S:" + v
		default:
			r.Panic = "?"
		}
	}
}

type sink struct{ data []byte }

func (s *sink) Write(p []byte) (int, error) { s.data = append(s.data, p...); return len(p), nil }

// WovenBuffer runs op through direct (woven) calls.
func WovenBuffer(h *BufHolder, op Op) (res Res) {
	defer recoverTo(&res)
	res.BsOff = -2
	p := &h.B
	switch op.Kind {
	case OpWrite:
		if op.Ptr {
			res.N, _ = p.Write(op.Bs)
		} else {
			res.N, _ = h.B.Write(op.Bs)
		}
	case OpWriteString:
		if op.Ptr {
			res.N, _ = p.WriteString(op.S)
		} else {
			res.N, _ = h.B.WriteString(op.S)
		}
	case OpWriteByte:
		var err error
		if op.Ptr {
			err = p.WriteByte(op.C)
		} else {
			err = h.B.WriteByte(op.C)
		}
		res.Err = errString(err)
	case OpWriteRune:
		if op.Ptr {
			res.N, _ = p.WriteRune(op.R)
		} else {
			res.N, _ = h.B.WriteRune(op.R)
		}
	case OpGrow:
		if op.Ptr {
			p.Grow(op.N)
		} else {
			h.B.Grow(op.N)
		}
	case OpReset:
		if op.Ptr {
			p.Reset()
		} else {
			h.B.Reset()
		}
	case OpTruncate:
		if op.Ptr {
			p.Truncate(op.N)
		} else {
			h.B.Truncate(op.N)
		}
	case OpString:
		res.HasS = true
		if op.Ptr {
			res.S = p.String()
		} else {
			res.S = h.B.String()
		}
	case OpRead:
		dst := make([]byte, op.N)
		var err error
		res.N, err = h.B.Read(dst)
		res.Err = errString(err)
		res.Bs, res.HasBs, res.BsOff = dst, true, -1
	case OpNext:
		res.Bs = h.B.Next(op.N)
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpReadByte:
		var err error
		res.C, err = h.B.ReadByte()
		res.Err = errString(err)
	case OpReadRune:
		var err error
		res.R, res.N, err = h.B.ReadRune()
		res.Err = errString(err)
	case OpUnreadByte:
		res.Err = errString(h.B.UnreadByte())
	case OpUnreadRune:
		res.Err = errString(h.B.UnreadRune())
	case OpReadBytes:
		var err error
		res.Bs, err = h.B.ReadBytes(op.C)
		res.Err = errString(err)
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpReadString:
		var err error
		res.S, err = h.B.ReadString(op.C)
		res.HasS = true
		res.Err = errString(err)
	case OpReadFrom:
		var err error
		res.N64, err = h.B.ReadFrom(strings.NewReader(op.S))
		res.Err = errString(err)
	case OpWriteTo:
		var s sink
		var err error
		res.N64, err = h.B.WriteTo(&s)
		res.Err = errString(err)
		res.Out = s.data
	case OpBytes:
		res.Bs = h.B.Bytes()
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpBytesMutate:
		bs := h.B.Bytes()
		if len(bs) > 0 {
			bs[op.N%len(bs)] = op.C
		}
	case OpAvailAppendWrite:
		ab := h.B.AvailableBuffer()
		ab = append(ab, op.S...)
		if op.Ptr {
			res.N, _ = p.Write(ab)
		} else {
			res.N, _ = h.B.Write(ab)
		}
	case OpPeek:
		var err error
		res.Bs, err = h.B.Peek(op.N)
		res.Err = errString(err)
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpPeekMutate:
		v, _ := h.B.Peek(op.N)
		for i := range v {
			v[i] = 'z'
		}
	case OpSelfWriteBytes:
		if op.Ptr {
			res.N, _ = p.Write(h.B.Bytes())
		} else {
			res.N, _ = h.B.Write(h.B.Bytes())
		}
	case OpSelfWriteString:
		if op.Ptr {
			res.N, _ = p.WriteString(p.String())
		} else {
			res.N, _ = h.B.WriteString(h.B.String())
		}
	case OpLenCap:
		res.N = h.B.Len()*1000000 + h.B.Cap()
		res.N64 = int64(h.B.Available())
	case OpCopyWrite:
		c := h.B
		res.N, _ = c.WriteString(op.S)
		res.HasS = true
		res.S = c.String()
	case OpNilRecv:
		var np *bytes.Buffer
		switch op.N % 9 {
		case 0:
			res.S = np.String()
			res.HasS = true
		case 1:
			np.WriteString(op.S)
		case 2:
			np.Write(op.Bs)
		case 3:
			np.WriteByte('x')
		case 4:
			np.WriteRune('x')
		case 5:
			np.Grow(1)
		case 6:
			np.Reset()
		case 7:
			np.Truncate(0)
		case 8:
			np.Grow(-1)
		}
	}
	return res
}

// WovenBuilder runs op through direct (woven) calls.
func WovenBuilder(h *BldHolder, op Op) (res Res) {
	defer recoverTo(&res)
	res.BsOff = -2
	p := &h.B
	switch op.Kind {
	case OpWrite:
		if op.Ptr {
			res.N, _ = p.Write(op.Bs)
		} else {
			res.N, _ = h.B.Write(op.Bs)
		}
	case OpWriteString:
		if op.Ptr {
			res.N, _ = p.WriteString(op.S)
		} else {
			res.N, _ = h.B.WriteString(op.S)
		}
	case OpWriteByte:
		if op.Ptr {
			res.Err = errString(p.WriteByte(op.C))
		} else {
			res.Err = errString(h.B.WriteByte(op.C))
		}
	case OpWriteRune:
		if op.Ptr {
			res.N, _ = p.WriteRune(op.R)
		} else {
			res.N, _ = h.B.WriteRune(op.R)
		}
	case OpGrow:
		if op.Ptr {
			p.Grow(op.N)
		} else {
			h.B.Grow(op.N)
		}
	case OpReset:
		if op.Ptr {
			p.Reset()
		} else {
			h.B.Reset()
		}
	case OpString:
		res.HasS = true
		if op.Ptr {
			res.S = p.String()
		} else {
			res.S = h.B.String()
		}
	case OpSelfWriteString:
		if op.Ptr {
			res.N, _ = p.WriteString(p.String())
		} else {
			res.N, _ = h.B.WriteString(h.B.String())
		}
	case OpLenCap:
		res.N = h.B.Len()*1000000 + h.B.Cap()
	case OpCopyWrite:
		c := h.B
		res.N, _ = c.WriteString(op.S)
		res.HasS = true
		res.S = c.String()
	case OpNilRecv:
		var np *strings.Builder
		switch op.N % 6 {
		case 0:
			res.S = np.String()
		case 1:
			np.WriteString(op.S)
		case 2:
			np.Write(op.Bs)
		case 3:
			np.WriteByte('x')
		case 4:
			np.Grow(1)
		case 5:
			np.Reset()
		}
	}
	return res
}

// ---- bytes package functions -------------------------------------------

// FnArgs are the inputs of one bytes.* call.
type FnArgs struct {
	Fn    int
	X     []byte
	Y     []byte
	Z     []byte
	Parts [][]byte
	Cut   string
	N     int
	Pred  int
}

// FnRes captures every result of one bytes.* call.
type FnRes struct {
	A, B  []byte
	HasA  bool
	HasB  bool
	List  [][]byte
	HasL  bool
	Ok    bool
	S     string
	Panic string
	Trace []rune
}

const FnCount = 31

// Pred returns a deterministic rune predicate that records its calls.
func Pred(kind int, trace *[]rune) func(rune) bool {
	return func(r rune) bool {
		*trace = append(*trace, r)
		switch kind % 4 {
		case 0:
			return r == ' ' || r == ',' || r == '\n'
		case 1:
			return r >= 0x80
		case 2:
			return r%3 == 0
		default:
			return r == 'a' || r == 0xFFFD
		}
	}
}

// Mapper returns a deterministic rune mapping that records its calls.
func Mapper(kind int, trace *[]rune) func(rune) rune {
	return func(r rune) rune {
		*trace = append(*trace, r)
		switch kind % 4 {
		case 0:
			return r + 1
		case 1:
			if r == 'a' || r == ',' {
				return -1
			}
			return r
		case 2:
			if r < 0x80 {
				return r + 0x100
			}
			return r
		default:
			return 'x'
		}
	}
}

// WovenFn runs one bytes.* call directly (woven).
func WovenFn(a FnArgs) (r FnRes) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				r.Panic = "E:" + e.Error()
			} else if s, ok := p.(string); ok {
				r.Panic = "S:" + s
			} else {
				r.Panic = "?"
			}
		}
	}()
	pred := Pred(a.Pred, &r.Trace)
	switch a.Fn {
	case 0:
		r.A, r.HasA = bytes.Clone(a.X), true
	case 1:
		r.A, r.HasA = bytes.Join(a.Parts, a.Y), true
	case 2:
		r.A, r.HasA = bytes.Repeat(a.X, a.N), true
	case 3:
		r.A, r.B, r.Ok = bytes.Cut(a.X, a.Y)
		r.HasA, r.HasB = true, true
	case 4:
		r.A, r.Ok = bytes.CutPrefix(a.X, a.Y)
		r.HasA = true
	case 5:
		r.A, r.Ok = bytes.CutSuffix(a.X, a.Y)
		r.HasA = true
	case 6:
		r.List, r.HasL = bytes.Split(a.X, a.Y), true
	case 7:
		r.List, r.HasL = bytes.SplitN(a.X, a.Y, a.N), true
	case 8:
		r.List, r.HasL = bytes.SplitAfter(a.X, a.Y), true
	case 9:
		r.List, r.HasL = bytes.SplitAfterN(a.X, a.Y, a.N), true
	case 10:
		r.List, r.HasL = bytes.Fields(a.X), true
	case 11:
		r.List, r.HasL = bytes.FieldsFunc(a.X, pred), true
	case 12:
		r.A, r.HasA = bytes.Trim(a.X, a.Cut), true
	case 13:
		r.A, r.HasA = bytes.TrimSpace(a.X), true
	case 14:
		r.A, r.HasA = bytes.TrimLeft(a.X, a.Cut), true
	case 15:
		r.A, r.HasA = bytes.TrimRight(a.X, a.Cut), true
	case 16:
		r.A, r.HasA = bytes.TrimPrefix(a.X, a.Y), true
	case 17:
		r.A, r.HasA = bytes.TrimSuffix(a.X, a.Y), true
	case 18:
		r.A, r.HasA = bytes.TrimFunc(a.X, pred), true
	case 19:
		r.A, r.HasA = bytes.TrimLeftFunc(a.X, pred), true
	case 20:
		r.A, r.HasA = bytes.TrimRightFunc(a.X, pred), true
	case 21:
		r.A, r.HasA = bytes.Replace(a.X, a.Y, a.Z, a.N), true
	case 22:
		r.A, r.HasA = bytes.ReplaceAll(a.X, a.Y, a.Z), true
	case 23:
		r.A, r.HasA = bytes.ToLower(a.X), true
	case 24:
		r.A, r.HasA = bytes.ToUpper(a.X), true
	case 25:
		r.A, r.HasA = bytes.ToTitle(a.X), true
	case 26:
		r.A, r.HasA = bytes.Map(Mapper(a.Pred, &r.Trace), a.X), true
	case 27:
		r.A, r.HasA = bytes.ToValidUTF8(a.X, a.Y), true
	case 28:
		lo, hi := a.N&0xff, (a.N>>8)&0xff
		r.A, r.HasA = a.X[lo:hi], true
	case 29:
		lo, hi, mx := a.N&0xff, (a.N>>8)&0xff, (a.N>>16)&0xff
		r.A, r.HasA = a.X[lo:hi:mx], true
	case 30:
		s := string(a.X)
		r.S = s
	}
	return r
}

var _ = io.EOF

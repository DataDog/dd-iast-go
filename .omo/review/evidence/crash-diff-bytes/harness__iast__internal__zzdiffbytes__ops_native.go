package zzdiffbytes

import (
	"bytes"
	"strings"
)

// NativeBuffer mirrors WovenBuffer using method values only, which the
// method-call join points do not match.
func NativeBuffer(h *BufHolder, op Op) (res Res) {
	defer recoverTo(&res)
	res.BsOff = -2
	p := &h.B
	switch op.Kind {
	case OpWrite:
		f := p.Write
		res.N, _ = f(op.Bs)
	case OpWriteString:
		f := p.WriteString
		res.N, _ = f(op.S)
	case OpWriteByte:
		f := p.WriteByte
		res.Err = errString(f(op.C))
	case OpWriteRune:
		f := p.WriteRune
		res.N, _ = f(op.R)
	case OpGrow:
		f := p.Grow
		f(op.N)
	case OpReset:
		f := p.Reset
		f()
	case OpTruncate:
		f := p.Truncate
		f(op.N)
	case OpString:
		f := p.String
		res.HasS = true
		res.S = f()
	case OpRead:
		dst := make([]byte, op.N)
		f := p.Read
		var err error
		res.N, err = f(dst)
		res.Err = errString(err)
		res.Bs, res.HasBs, res.BsOff = dst, true, -1
	case OpNext:
		f := p.Next
		res.Bs = f(op.N)
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpReadByte:
		f := p.ReadByte
		var err error
		res.C, err = f()
		res.Err = errString(err)
	case OpReadRune:
		f := p.ReadRune
		var err error
		res.R, res.N, err = f()
		res.Err = errString(err)
	case OpUnreadByte:
		f := p.UnreadByte
		res.Err = errString(f())
	case OpUnreadRune:
		f := p.UnreadRune
		res.Err = errString(f())
	case OpReadBytes:
		f := p.ReadBytes
		var err error
		res.Bs, err = f(op.C)
		res.Err = errString(err)
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpReadString:
		f := p.ReadString
		var err error
		res.S, err = f(op.C)
		res.HasS = true
		res.Err = errString(err)
	case OpReadFrom:
		f := p.ReadFrom
		var err error
		res.N64, err = f(strings.NewReader(op.S))
		res.Err = errString(err)
	case OpWriteTo:
		var s sink
		f := p.WriteTo
		var err error
		res.N64, err = f(&s)
		res.Err = errString(err)
		res.Out = s.data
	case OpBytes:
		f := p.Bytes
		res.Bs = f()
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpBytesMutate:
		f := p.Bytes
		bs := f()
		if len(bs) > 0 {
			bs[op.N%len(bs)] = op.C
		}
	case OpAvailAppendWrite:
		fa := p.AvailableBuffer
		ab := fa()
		ab = append(ab, op.S...)
		f := p.Write
		res.N, _ = f(ab)
	case OpPeek:
		f := p.Peek
		var err error
		res.Bs, err = f(op.N)
		res.Err = errString(err)
		res.HasBs, res.BsOff = true, AliasOff(res.Bs, BufBase(p))
	case OpPeekMutate:
		f := p.Peek
		v, _ := f(op.N)
		for i := range v {
			v[i] = 'z'
		}
	case OpSelfWriteBytes:
		fb := p.Bytes
		f := p.Write
		res.N, _ = f(fb())
	case OpSelfWriteString:
		fs := p.String
		f := p.WriteString
		res.N, _ = f(fs())
	case OpLenCap:
		fl, fc, fa := p.Len, p.Cap, p.Available
		res.N = fl()*1000000 + fc()
		res.N64 = int64(fa())
	case OpCopyWrite:
		c := h.B
		f := (&c).WriteString
		res.N, _ = f(op.S)
		fs := (&c).String
		res.HasS = true
		res.S = fs()
	case OpNilRecv:
		var np *bytes.Buffer
		switch op.N % 9 {
		case 0:
			f := np.String
			res.S = f()
			res.HasS = true
		case 1:
			f := np.WriteString
			f(op.S)
		case 2:
			f := np.Write
			f(op.Bs)
		case 3:
			f := np.WriteByte
			f('x')
		case 4:
			f := np.WriteRune
			f('x')
		case 5:
			f := np.Grow
			f(1)
		case 6:
			f := np.Reset
			f()
		case 7:
			f := np.Truncate
			f(0)
		case 8:
			f := np.Grow
			f(-1)
		}
	}
	return res
}

// NativeBuilder mirrors WovenBuilder using method values only.
func NativeBuilder(h *BldHolder, op Op) (res Res) {
	defer recoverTo(&res)
	res.BsOff = -2
	p := &h.B
	switch op.Kind {
	case OpWrite:
		f := p.Write
		res.N, _ = f(op.Bs)
	case OpWriteString:
		f := p.WriteString
		res.N, _ = f(op.S)
	case OpWriteByte:
		f := p.WriteByte
		res.Err = errString(f(op.C))
	case OpWriteRune:
		f := p.WriteRune
		res.N, _ = f(op.R)
	case OpGrow:
		f := p.Grow
		f(op.N)
	case OpReset:
		f := p.Reset
		f()
	case OpString:
		f := p.String
		res.HasS = true
		res.S = f()
	case OpSelfWriteString:
		fs := p.String
		f := p.WriteString
		res.N, _ = f(fs())
	case OpLenCap:
		fl, fc := p.Len, p.Cap
		res.N = fl()*1000000 + fc()
	case OpCopyWrite:
		c := h.B
		f := (&c).WriteString
		res.N, _ = f(op.S)
		fs := (&c).String
		res.HasS = true
		res.S = fs()
	case OpNilRecv:
		var np *strings.Builder
		switch op.N % 6 {
		case 0:
			// Evaluating the method value np.String panics at binding time
			// for a nil pointer only when the method needs a dereference; bind
			// through a closure to keep the panic inside the call.
			f := (*strings.Builder).String
			res.S = f(np)
		case 1:
			f := (*strings.Builder).WriteString
			f(np, op.S)
		case 2:
			f := (*strings.Builder).Write
			f(np, op.Bs)
		case 3:
			f := (*strings.Builder).WriteByte
			f(np, 'x')
		case 4:
			f := (*strings.Builder).Grow
			f(np, 1)
		case 5:
			f := (*strings.Builder).Reset
			f(np)
		}
	}
	return res
}

var (
	nClone       = bytes.Clone
	nJoin        = bytes.Join
	nRepeat      = bytes.Repeat
	nCut         = bytes.Cut
	nCutPrefix   = bytes.CutPrefix
	nCutSuffix   = bytes.CutSuffix
	nSplit       = bytes.Split
	nSplitN      = bytes.SplitN
	nSplitAfter  = bytes.SplitAfter
	nSplitAfterN = bytes.SplitAfterN
	nFields      = bytes.Fields
	nFieldsFunc  = bytes.FieldsFunc
	nTrim        = bytes.Trim
	nTrimSpace   = bytes.TrimSpace
	nTrimLeft    = bytes.TrimLeft
	nTrimRight   = bytes.TrimRight
	nTrimPrefix  = bytes.TrimPrefix
	nTrimSuffix  = bytes.TrimSuffix
	nTrimFunc    = bytes.TrimFunc
	nTrimLeftFn  = bytes.TrimLeftFunc
	nTrimRightFn = bytes.TrimRightFunc
	nReplace     = bytes.Replace
	nReplaceAll  = bytes.ReplaceAll
	nToLower     = bytes.ToLower
	nToUpper     = bytes.ToUpper
	nToTitle     = bytes.ToTitle
	nMap         = bytes.Map
	nToValidUTF8 = bytes.ToValidUTF8
)

// NativeFn runs one bytes.* call through function values.
func NativeFn(a FnArgs) (r FnRes) {
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
		r.A, r.HasA = nClone(a.X), true
	case 1:
		r.A, r.HasA = nJoin(a.Parts, a.Y), true
	case 2:
		r.A, r.HasA = nRepeat(a.X, a.N), true
	case 3:
		r.A, r.B, r.Ok = nCut(a.X, a.Y)
		r.HasA, r.HasB = true, true
	case 4:
		r.A, r.Ok = nCutPrefix(a.X, a.Y)
		r.HasA = true
	case 5:
		r.A, r.Ok = nCutSuffix(a.X, a.Y)
		r.HasA = true
	case 6:
		r.List, r.HasL = nSplit(a.X, a.Y), true
	case 7:
		r.List, r.HasL = nSplitN(a.X, a.Y, a.N), true
	case 8:
		r.List, r.HasL = nSplitAfter(a.X, a.Y), true
	case 9:
		r.List, r.HasL = nSplitAfterN(a.X, a.Y, a.N), true
	case 10:
		r.List, r.HasL = nFields(a.X), true
	case 11:
		r.List, r.HasL = nFieldsFunc(a.X, pred), true
	case 12:
		r.A, r.HasA = nTrim(a.X, a.Cut), true
	case 13:
		r.A, r.HasA = nTrimSpace(a.X), true
	case 14:
		r.A, r.HasA = nTrimLeft(a.X, a.Cut), true
	case 15:
		r.A, r.HasA = nTrimRight(a.X, a.Cut), true
	case 16:
		r.A, r.HasA = nTrimPrefix(a.X, a.Y), true
	case 17:
		r.A, r.HasA = nTrimSuffix(a.X, a.Y), true
	case 18:
		r.A, r.HasA = nTrimFunc(a.X, pred), true
	case 19:
		r.A, r.HasA = nTrimLeftFn(a.X, pred), true
	case 20:
		r.A, r.HasA = nTrimRightFn(a.X, pred), true
	case 21:
		r.A, r.HasA = nReplace(a.X, a.Y, a.Z, a.N), true
	case 22:
		r.A, r.HasA = nReplaceAll(a.X, a.Y, a.Z), true
	case 23:
		r.A, r.HasA = nToLower(a.X), true
	case 24:
		r.A, r.HasA = nToUpper(a.X), true
	case 25:
		r.A, r.HasA = nToTitle(a.X), true
	case 26:
		r.A, r.HasA = nMap(Mapper(a.Pred, &r.Trace), a.X), true
	case 27:
		r.A, r.HasA = nToValidUTF8(a.X, a.Y), true
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

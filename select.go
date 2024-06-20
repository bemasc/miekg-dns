package dns

import (
	"slices"
)

type SELECT struct {
	Hdr        RR_Header
	Selector   string
	Base       string   `dns:"domain-name"`
	TypeBitMap []uint16 `dns:"nsec"`
}

func (rr *SELECT) String() string {
	s := rr.Hdr.String() + sprintTxt([]string{rr.Selector}) + " " + sprintName(rr.Base)
	for _, t := range rr.TypeBitMap {
		s += " " + Type(t).String()
	}
	return s
}

func (rr *SELECT) parse(c *zlexer, o string) *ParseError {
	selector, err := readCharacterString(c, "SELECT selector")
	if err != nil {
		return err
	}
	if selector == nil {
		return &ParseError{err: "SELECT has no RDATA"}
	}
	rr.Selector = *selector

	l, _ := c.Next()
	if l.err {
		return &ParseError{err: "missing SELECT base name", lex: l}
	}
	if l.value != zBlank {
		return &ParseError{err: "SELECT selector must be followed by a blank", lex: l}
	}

	rr.Base, rr.TypeBitMap, err = parseNSEC(c, o)
	return err
}

func (rr *SELECT) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packStringTxt([]string{rr.Selector}, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packDomainName(rr.Base, msg, off, compression, false)
	if err != nil {
		return off, err
	}
	off, err = packDataNsec(rr.TypeBitMap, msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *SELECT) unpack(msg []byte, off int) (off1 int, err error) {
	rr.Selector, off, err = unpackString(msg, off)
	if err != nil {
		return off, err
	}
	if off == len(msg) {
		return off, nil
	}
	rr.Base, off, err = UnpackDomainName(msg, off)
	if err != nil {
		return off, err
	}
	if off == len(msg) {
		return off, nil
	}
	rr.TypeBitMap, off, err = unpackDataNsec(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *SELECT) len(off int, compression map[string]struct{}) int {
	l := rr.Hdr.len(off, compression)
	l += len(rr.Selector) + 1
	l += domainNameLen(rr.Base, off+l, compression, false)
	l += typeBitMapLen(rr.TypeBitMap)
	return l
}

func (rr *SELECT) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*SELECT)
	if !ok {
		return false
	}
	_ = r2
	if !isDuplicateName(rr.Base, r2.Base) {
		return false
	}
	if !slices.Equal(rr.TypeBitMap, r2.TypeBitMap) {
		return false
	}
	return true
}

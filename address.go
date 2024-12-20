package windivert

import "github.com/imgk/divert-go"

type Address struct {
	*divert.Address
}

// https://github.com/Jamesits/go-windivert/blob/master/pkg/ffi/enums.go
type Direction int

const (
	Outbound Direction = 1
	Inbound  Direction = 0
)

func (a *Address) Direction() Direction {
	if a.Flags&0x80 > 0 {
		return Outbound
	}
	return Inbound
}

func (a *Address) SetDirection(d Direction) {
	if d == Outbound {
		a.Flags |= 0x80
	} else {
		a.Flags &= 0x7f
	}
}

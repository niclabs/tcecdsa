package tcecdsa

import (
	"crypto/elliptic"
	"github.com/niclabs/tcecdsa/l2fhe"
	"io"
	"math/big"
)

type Params struct {
	K, L       uint8
	N          *big.Int
	Curve      elliptic.Curve // Elliptic Curve used
	RandomSrc  io.Reader      // Random Source
	PaillierPK *l2fhe.Paillier
	*ZKProofMeta
}

// Returns Curve Subfield bitlength
func (p *Params) Q() *big.Int {
	return p.Curve.Params().N
}
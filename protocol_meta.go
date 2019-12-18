package tcecdsa

import (
	"crypto/elliptic"
	"github.com/actuallyachraf/gomorph/gaillier"
	"io"
	"math/big"
)

type KeyMeta struct {
	T          uint8
	PaillierPK *gaillier.PubKey
	N          *big.Int
	Curve      elliptic.Curve
	RandomSrc  io.Reader
	PubKeys    []*Point
	NTilde     *big.Int // Used in ZK Proofs
	H1         *big.Int // Used in ZK Proofs
	H2         *big.Int // Used in ZK Proofs
	Alpha      []byte
	Y          *Point
}

// Returns Curve Subfield bitlength
func (p *KeyMeta) Q() *big.Int {
	return p.Curve.Params().N
}

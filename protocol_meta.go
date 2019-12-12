package tcecdsa

import (
	"crypto/elliptic"
	"github.com/actuallyachraf/gomorph/gaillier"
	"io"
	"math/big"
)

type PubMeta struct {
	T          uint8
	PaillierPK *gaillier.PubKey
	Curve      elliptic.Curve
	RandomSrc  io.Reader
	PubKeys    []*Point
	NTilde     *big.Int // Used in ZK Proofs
	H1         *big.Int // Used in ZK Proofs
	H2         *big.Int // Used in ZK Proofs
}

// Returns Curve Subfield bitlength
func (p *PubMeta) Q() *big.Int {
	return p.Curve.Params().N
}

// Returns Paillier Keysize
func (p *PubMeta) N() *big.Int {
	return new(big.Int).Exp(p.Q(), big.NewInt((3*int64(p.T) + 2)), nil)
}

type PrivMeta struct {
	PaillierSK *gaillier.PrivKey
}

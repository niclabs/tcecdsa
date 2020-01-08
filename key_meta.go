package tcecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/niclabs/tcecdsa/l2fhe"
	"hash"
	"io"
	"math/big"
)

type KeyMeta struct {
	*l2fhe.PubKey
	*ZKProofMeta
	Curve elliptic.Curve
	Hash hash.Hash
}

// Returns Curve Subfield bitlength
func (meta *KeyMeta) Q() *big.Int {
	return meta.Curve.Params().N
}

func (meta *KeyMeta) RandomSource() io.Reader {
	return meta.Paillier.RandSource
}

func (meta *KeyMeta) G() *Point {
	return &Point{
		X: new(big.Int).Set(meta.Curve.Params().Gx),
		Y: new(big.Int).Set(meta.Curve.Params().Gy),
	}
}

func (meta *KeyMeta) GetKeys(msgs ...*KeyInitMessage) (pk *ecdsa.PublicKey, err error) {
	_, y, err := meta.joinKeyInit(msgs...)
	if err != nil {
		return
	}
	pk = &ecdsa.PublicKey{
		Curve: meta.Curve,
		X:     y.X,
		Y:     y.Y,
	}
	return
}
package tcecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/niclabs/tcecdsa/l2fhe"
	"hash"
	"io"
	"math/big"
)

// KeyMeta represents a set of parameters that are used by every key share.
type KeyMeta struct {
	*l2fhe.PubKey                // L2FHE Public Key
	*ZKProofMeta                 // Parameters used by ZK Proofs
	Curve         elliptic.Curve // Elliptic curve used by the signing protocol
	Hash          hash.Hash      // Hash used by the signing protocol
}

// Q returns Curve Subfield bitlength (referred internally as N, but as Q on papers).
func (meta *KeyMeta) Q() *big.Int {
	return meta.Curve.Params().N
}

// RandomSource returns the random source used.
func (meta *KeyMeta) RandomSource() io.Reader {
	return meta.Paillier.RandSource
}

// G returns the base point of the curve, as a *Point.
func (meta *KeyMeta) G() *Point {
	return &Point{
		X: new(big.Int).Set(meta.Curve.Params().Gx),
		Y: new(big.Int).Set(meta.Curve.Params().Gy),
	}
}

// GetPublicKey parses the key init messages and returns the public key of the signature scheme.
func (meta *KeyMeta) GetPublicKey(msgs KeyInitMessageList) (pk *ecdsa.PublicKey, err error) {
	_, y, err := msgs.Join(meta)
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

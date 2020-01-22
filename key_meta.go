package tcecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"math/big"
)

// KeyMeta represents a set of parameters that are used by every key share.
type KeyMeta struct {
	*l2fhe.PubKey                 // L2FHE Public Key
	*ZKProofMeta                   // Parameters used by ZK Proofs
	curve         elliptic.Curve // Elliptic curve used by the signing protocol
	CurveName     string
}


func (meta *KeyMeta) Curve() elliptic.Curve {
	if meta.curve == nil {
		curve, ok := CurveNameToCurve[meta.CurveName]
		if !ok {
			panic(fmt.Errorf("curve with name %s unsupported", meta.CurveName))
		}
		meta.curve = curve
	}
	return meta.curve
}

// Q returns curve Subfield bitlength (referred internally as N, but as Q on papers).
func (meta *KeyMeta) Q() *big.Int {
	return meta.Curve().Params().N
}

// G returns the base point of the curve, as a *Point.
func (meta *KeyMeta) G() *Point {
	return &Point{
		X: new(big.Int).Set(meta.Curve().Params().Gx),
		Y: new(big.Int).Set(meta.Curve().Params().Gy),
	}
}

// GetPublicKey parses the key init messages and returns the public key of the Signature scheme.
func (meta *KeyMeta) GetPublicKey(msgs KeyInitMessageList) (pk *ecdsa.PublicKey, err error) {
	_, y, err := msgs.Join(meta)
	if err != nil {
		return
	}
	pk = &ecdsa.PublicKey{
		Curve: meta.Curve(),
		X:     y.X,
		Y:     y.Y,
	}
	return
}

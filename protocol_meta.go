package tcecdsa

import (
	"crypto/elliptic"
	"github.com/actuallyachraf/gomorph/gaillier"
	"io"
	"math/big"
)

type KeyMeta struct {
	T           uint8
	PaillierPK  *gaillier.PubKey // Paillier PK
	N           *big.Int         // Paillier moduli
	Curve       elliptic.Curve   // Elliptic Curve used
	RandomSrc   io.Reader        // Random Source
	PubKeys     []*Point         // Individual Public Keys
	Alpha       []byte           // Encripted private key
	Y           *Point           // Public Key
}

type ZKProofMeta struct {
	NTilde *big.Int // Used in ZK Proofs
	H1     *big.Int // Used in ZK Proofs
	H2     *big.Int // Used in ZK Proofs
}

// Returns Curve Subfield bitlength
func (p *KeyMeta) Q() *big.Int {
	return p.Curve.Params().N
}

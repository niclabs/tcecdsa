package l2fhe

import (
	"github.com/niclabs/tcpaillier"
	"io"
	"math/big"
)

// L2TCPaillier represents the use of Pallier Threshold Cryptosystem
// with Catalano-Fiore's Level-1 Homomorphic Encryption.
// This implementation is based on TCECDSA paper, using some missing
// definitions from the original paper.
type L2TCPaillier struct {
	PubKey           *tcpaillier.PubKey
	MaxMessageModule *big.Int
}

func NewL2TCPaillier(msgBitSize int, l, k uint8, randSource io.Reader) (l1tc *L2TCPaillier, keyShares []*tcpaillier.KeyShare, err error) {
	keyShares, pk, err := tcpaillier.NewKey(4*msgBitSize, 1, l, k, randSource) // S is fixed to 1 because this is the version the paper uses.
	maxMessageModule := new(big.Int)
	maxMessageModule.SetBit(maxMessageModule, msgBitSize, 1)
		l1tc = &L2TCPaillier{
		PubKey:     pk,
		MaxMessageModule: maxMessageModule,
	}
	return
}

// Encrypt encrypts a value using TCPaillier and Catalano-Fiore, generating
// a Level-0 value.
func (l *L2TCPaillier) Encrypt(m []byte) (e *EncryptedL1, err error) {
	b, err := rand.Int(l.PubKey.RandSource, l.MaxMessageModule)
	if err != nil {
		return
	}
	bigM := new(big.Int).SetBytes(m)
	encB, proof, err := l.PubKey.Encrypt(b.Bytes())
	if err != nil {
		return
	}
	e = &EncryptedL1{
		Alpha:  new(big.Int).Sub(bigM, b),
		Beta:   encB,
		Proofs: make([]tcpaillier.ZKProof, 0),
	}
	e.Proofs = append(e.Proofs, proof)
	return
}

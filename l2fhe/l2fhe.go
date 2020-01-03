package l2fhe

import (
	"crypto/rand"
	"github.com/niclabs/tcpaillier"
	"io"
	"math/big"
)

// Paillier in l2fhe module represents the use of Pallier Threshold Cryptosystem
// with Catalano-Fiore's Level-1 Homomorphic Encryption.
// This implementation is based on TCECDSA paper, using some missing
// definitions from the original paper.
type Paillier struct {
	PK               *tcpaillier.PubKey
	MaxMessageModule *big.Int
}

func NewKey(msgBitSize int, l, k uint8, randSource io.Reader) (pubKey *Paillier, keyShares []*tcpaillier.KeyShare, err error) {
	keyShares, pk, err := tcpaillier.NewKey(8*msgBitSize, 1, l, k, randSource) // S is fixed to 1 because this is the version the paper uses.
	if err != nil {
		return
	}
	maxMessageModule := new(big.Int)
	maxMessageModule.SetBit(maxMessageModule, msgBitSize, 1)
	pubKey = &Paillier{
		PK:               pk,
		MaxMessageModule: maxMessageModule,
	}
	return
}

// Encrypt encrypts a value using TCPaillier and Catalano-Fiore, generating
// a Level-1 value.
func (l *Paillier) Encrypt(m *big.Int) (e *EncryptedL1, zk ZKProof, err error) {
	b, err := rand.Int(l.PK.RandSource, l.MaxMessageModule)
	if err != nil {
		return
	}
	encB, proof, err := l.PK.Encrypt(b)
	if err != nil {
		return
	}
	e = &EncryptedL1{
		Alpha: new(big.Int).Sub(m, b),
		Beta:  encB,
	}
	zk = &EncryptedL1ZK{beta: proof}
	return
}

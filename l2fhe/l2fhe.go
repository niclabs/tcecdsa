// Package l2fhe represents a homomorphic encryption scheme based on Catalano-Fiore and Paillier Cryptosystem.
// this scheme supports multiplication of two level-1 (not previously multiplicated while encrypted) encrypted
// values, and also the properties of classic Paillier.
package l2fhe

import (
	"crypto/rand"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

// PubKey in l2fhe module represents the use of Pallier Threshold Cryptosystem
// with Catalano-Fiore's Level-1 Homomorphic Encryption.
// This implementation is based on TCECDSA paper, using some missing
// definitions from the original paper.
// This implementation does not consider ZK Proofs for encryption and multiplication values,
// Because the ECDSA paper uses other ZKProofs.
type PubKey struct {
	Paillier         *tcpaillier.PubKey
	MaxMessageModule *big.Int
}

// NewKey returns a new L2FHE Key, based on PubKey Threshold Cryptosystem.
func NewKey(msgBitSize int, l, k uint8) (pubKey *PubKey, keyShares []*tcpaillier.KeyShare, err error) {
	keyShares, pk, err := tcpaillier.NewKey(8*msgBitSize, 1, l, k) // s is fixed to 1 because this is the version the paper uses.
	if err != nil {
		return
	}
	maxMessageModule := new(big.Int)
	maxMessageModule.SetBit(maxMessageModule, msgBitSize, 1)
	pubKey = &PubKey{
		Paillier:         pk,
		MaxMessageModule: maxMessageModule,
	}
	return
}

// NewFixedKey returns a new L2FHE Key, based on PubKey Threshold Cryptosystem, using a fixed set of params for tcpaillier.
func NewFixedKey(msgBitSize int, l, k uint8, params *tcpaillier.FixedParams) (pubKey *PubKey, keyShares []*tcpaillier.KeyShare, err error) {
	keyShares, pk, err := tcpaillier.NewFixedKey(8*msgBitSize, 1, l, k, params) // s is fixed to 1 because this is the version the paper uses.
	if err != nil {
		return
	}
	maxMessageModule := new(big.Int)
	maxMessageModule.SetBit(maxMessageModule, msgBitSize, 1)
	pubKey = &PubKey{
		Paillier:         pk,
		MaxMessageModule: maxMessageModule,
	}
	return
}

// Encrypt encrypts a value using TCPaillier and Catalano-Fiore, generating
// a Level-1 value. It returns also the random value used to encrypt.
func (l *PubKey) Encrypt(m *big.Int) (e *EncryptedL1, r *big.Int, err error) {
	r, err = l.Paillier.RandomModNToSPlusOneStar()
	if err != nil {
		return
	}
	e, err = l.EncryptFixed(m, r)
	return
}

// EncryptFixed encrypts a value using TCPaillier and Catalano-Fiore, generating
// a Level-1 value, using a defined randomness.
func (l *PubKey) EncryptFixed(m, r *big.Int) (e *EncryptedL1, err error) {
	b, err := rand.Int(rand.Reader, l.MaxMessageModule)
	if err != nil {
		return
	}
	return l.EncryptFixedB(m, r, b)
}

// EncryptFixedB encrypts a value using TCPaillier and Catalano-Fiore, generating
// a Level-1 value, using a defined randomness and a b value.
func (l *PubKey) EncryptFixedB(m, r, b *big.Int) (e *EncryptedL1, err error) {
	encB, err := l.Paillier.EncryptFixed(b, r)
	if err != nil {
		return
	}
	e = &EncryptedL1{
		Alpha: new(big.Int).Sub(m, b),
		Beta:  encB,
	}
	return
}

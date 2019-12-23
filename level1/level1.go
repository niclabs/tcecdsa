package level1

import (
	"math/big"
	"github.com/niclabs/tcpaillier"
)

// L1TCPaillier represents the use of Pallier Threshold Cryptosystem
// with Catalano-Fiore's Level-1 Homomorphic Encryption.
// This implementation is based on TCECDSA paper, using some missing
// definitions from the original paper.
type L1TCPaillier struct {
	PubKey tcpaillier.PubKey
}

type EncryptedLevel0 struct {
	Alpha, Beta *big.Int
}

type EncryptedLevel1 struct {
	Alpha *big.Int
	Betas []BetaPair
}

type BetaPair struct {
	Beta1, Beta2 *big.Int
}

type DecryptedShare struct {
	Share tcpaillier.DecryptionShare
	Proofs []tcpaillier.ZKProof
}

func (l *L1TCPaillier) Encrypt(b []byte) (*EncryptedLevel0, error) {

}

func (l *L1TCPaillier) AddLevel0(c1, c2 *EncryptedLevel0) (sum *EncryptedLevel0, err error) {

}

func (l *L1TCPaillier) AddLevel1(c1, c2 *EncryptedLevel1) (sum *EncryptedLevel1, err error) {

}

func (l *L1TCPaillier) Mul(c1, c2 *EncryptedLevel0) (mul *EncryptedLevel1, err error) {

}

func (l *L1TCPaillier) MulConstLevel0(c1 *EncryptedLevel0, c2 *big.Int) (mul *EncryptedLevel1, err error) {

}

func (l *L1TCPaillier) MulConstLevel1(c1 *EncryptedLevel0, c2 *big.Int) (mul *EncryptedLevel1, err error) {

}

func (l *L1TCPaillier) PartialDecrypt() (share, DecryptedShare, err error) {

}

func (l *L1TCPaillier) CombineShares(shares ...DecryptedShare) (decrypted []byte, err error) {

}
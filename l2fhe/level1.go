package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

var one = big.NewInt(1)

// EncryptedL1 represents a Level-1 Encrypted value.
type EncryptedL1 struct {
	Alpha *big.Int
	Beta  *big.Int
}

// DecryptedShareL1 represents a Level-1 Decrypted share.
type DecryptedShareL1 struct {
	Alpha *big.Int
	Beta  *tcpaillier.DecryptionShare
}

// Clone clones an EncryptedL1 value.
func (L1 *EncryptedL1) Clone() *EncryptedL1 {
	return &EncryptedL1{
		Alpha: new(big.Int).Set(L1.Alpha),
		Beta:  new(big.Int).Set(L1.Beta),
	}
}

// ToPaillier transforms a Level-1 Encrypted value to a PubKey encrypted value,
// compatible with tcpaillier library.
func (L1 *EncryptedL1) ToPaillier(pk *tcpaillier.PubKey) (c *big.Int, err error) {
	// Create E(m) = E(alpha) + E(b) = E(m-b) + E(b) from c
	encAlpha, err := pk.EncryptFixed(L1.Alpha, one)
	if err != nil {
		return
	}
	c, err = pk.Add(L1.Beta, encAlpha)
	return
}

// Returns a deterministic representation of a L1 value to L2
func (L1 *EncryptedL1) ToL2(pk *PubKey) (l2 *EncryptedL2, err error) {
	oneEncrypted, _ := pk.EncryptFixed(one, one)
	return pk.Mul(L1, oneEncrypted)
}

// AddL1 adds a list of Encrypted Level-1 values and returns its encrypted sum.
func (l *PubKey) AddL1(cList ...*EncryptedL1) (sum *EncryptedL1, err error) {
	if len(cList) == 0 {
		err = fmt.Errorf("empty encrypted list")
		return
	}
	betaSum := new(big.Int).Set(cList[0].Beta)
	alphaSum := new(big.Int).Set(cList[0].Alpha)
	for i := 1; i < len(cList); i++ {
		c := cList[i]
		betaSum, err = l.Paillier.Add(betaSum, c.Beta)
		if err != nil {
			return
		}
		alphaSum = alphaSum.Add(alphaSum, c.Alpha)
	}

	sum = &EncryptedL1{
		Alpha: alphaSum,
		Beta:  betaSum,
	}
	return
}

// MulConstL1 multiplies an Encrypted Level-1 value by a constant.
// The encryption is deterministic.
// TODO: check if we can use the normal zkproofs to create a zkproof for this case. Meanwhile, we have no ZKProofs.
func (l *PubKey) MulConstL1(c *EncryptedL1, cons *big.Int) (mul *EncryptedL1, err error) {
	mulBeta, err := l.Paillier.MultiplyFixed(c.Beta, cons, one)
	if err != nil {
		return
	}
	mulAlpha := new(big.Int).Mul(c.Alpha, cons)
	mul = &EncryptedL1{
		Alpha: mulAlpha,
		Beta:  mulBeta,
	}
	return
}

// PartialDecryptL1 decrypts partially an encrypted Level-1 value using a given key share. It returns the decrypted
// share and a ZKProof over the encrypted value.
func (l *PubKey) PartialDecryptL1(key *tcpaillier.KeyShare, c *EncryptedL1) (share *DecryptedShareL1, zk *DecryptedShareL1ZK, err error) {
	partialDecryptBeta, zkp, err := key.PartialDecryptWithProof(c.Beta)
	if err != nil {
		return
	}
	share = &DecryptedShareL1{
		Alpha: c.Alpha,
		Beta:  partialDecryptBeta,
	}
	zk = &DecryptedShareL1ZK{beta: zkp}
	return
}

// CombineSharesL1 joins a list of decryption shares, returning the decrypted value.
func (l *PubKey) CombineSharesL1(shares ...*DecryptedShareL1) (decrypted *big.Int, err error) {
	if len(shares) == 0 {
		err = fmt.Errorf("empty share list")
		return
	}
	// D = Alpha + D(Beta)
	betas := make([]*tcpaillier.DecryptionShare, 0)
	for _, share := range shares {
		betas = append(betas, share.Beta)
	}
	decrypt, err := l.Paillier.CombineShares(betas...)
	if err != nil {
		return
	}
	decrypted = new(big.Int).Add(decrypt, shares[0].Alpha)
	decrypted.Mod(decrypted, l.Paillier.N)
	return
}

// Mul multiplies two Encrypted Level-1 values and returns an encrypted Level-2 value.
// The mul encryption is deterministic.
func (l *PubKey) Mul(c1, c2 *EncryptedL1) (mul *EncryptedL2, err error) {
	alpha1Alpha2 := new(big.Int).Mul(c1.Alpha, c2.Alpha)
	alpha1Alpha2.Mod(alpha1Alpha2, l.Paillier.N)
	a1a2, err := l.Paillier.EncryptFixed(alpha1Alpha2, one)
	if err != nil {
		return
	}
	a2b1, err := l.Paillier.MultiplyFixed(c1.Beta, c2.Alpha, one)
	if err != nil {
		return
	}
	a1b2, err := l.Paillier.MultiplyFixed(c2.Beta, c1.Alpha, one)
	if err != nil {
		return
	}
	newAlpha, err := l.Paillier.Add(a1a2, a2b1, a1b2)
	if err != nil {
		return
	}
	mul = &EncryptedL2{
		Alpha: newAlpha,
		Betas: make([]*Betas, 0),
	}
	mul.Betas = append(mul.Betas, &Betas{
		Beta1: new(big.Int).Set(c1.Beta),
		Beta2: new(big.Int).Set(c2.Beta),
	})
	return
}

package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

var one = big.NewInt(1)

type EncryptedL1 struct {
	Alpha *big.Int
	Beta  *big.Int
}

type DecryptedShareL1 struct {
	Alpha *big.Int
	Beta  *tcpaillier.DecryptionShare
}

func (L1 *EncryptedL1) Clone() *EncryptedL1 {
	return &EncryptedL1{
		Alpha: new(big.Int).Set(L1.Alpha),
		Beta:  new(big.Int).Set(L1.Beta),
	}
}

func (l *Paillier) AddL1(cList ...*EncryptedL1) (sum *EncryptedL1, err error) {
	if len(cList) == 0 {
		err = fmt.Errorf("empty encrypted list")
		return
	}
	betaSum := new(big.Int).Set(cList[0].Beta)
	alphaSum := new(big.Int).Set(cList[0].Alpha)
	for i := 1; i < len(cList); i++ {
		c := cList[i]
		betaSum, err = l.PK.Add(betaSum, c.Beta)
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

func (l *Paillier) Mul(c1, c2 *EncryptedL1) (mul *EncryptedL2, zk ZKProof, err error) {
	alpha1Alpha2 := new(big.Int).Mul(c1.Alpha, c2.Alpha)
	alpha1Alpha2.Mod(alpha1Alpha2, l.PK.N)
	a1a2, a1a2proof, err := l.PK.EncryptFixed(alpha1Alpha2, one)
	if err != nil {
		return
	}
	a2b1, a2b1Proof, err := l.PK.Multiply(c1.Beta, c2.Alpha)
	if err != nil {
		return
	}
	a1b2, a1b2Proof, err := l.PK.Multiply(c2.Beta, c1.Alpha)
	if err != nil {
		return
	}
	newAlpha, err := l.PK.Add(a1a2, a2b1, a1b2)
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
	zk = &MulZK{
		a1a2:      a1a2,
		a1a2Proof: a1a2proof,
		a2b1:      a2b1,
		a2b1Proof: a2b1Proof,
		a1b2:      a1b2,
		a1b2Proof: a1b2Proof,
	}
	return
}

func (l *Paillier) MulConstL1(c *EncryptedL1, cons *big.Int) (mul *EncryptedL1, zk ZKProof, err error) {
	mulBeta, zkp, err := l.PK.Multiply(c.Beta, cons)
	if err != nil {
		return
	}
	mulAlpha := new(big.Int).Mul(c.Alpha, cons)
	mul = &EncryptedL1{
		Alpha: mulAlpha,
		Beta:  mulBeta,
	}
	zk = &EncryptedL1ZK{beta: zkp}
	return
}

func (l *Paillier) PartialDecryptL1(key *tcpaillier.KeyShare, c *EncryptedL1) (share *DecryptedShareL1, zk ZKProof, err error) {
	partialDecryptBeta, zkp, err := key.Decrypt(c.Beta)
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

func (l *Paillier) CombineSharesL1(shares ...*DecryptedShareL1) (decrypted *big.Int, err error) {
	if len(shares) == 0 {
		err = fmt.Errorf("empty share list")
		return
	}
	// D = Alpha + D(Beta)
	betas := make([]*tcpaillier.DecryptionShare, 0)
	for _, share := range shares {
		betas = append(betas, share.Beta)
	}
	decrypt, err := l.PK.CombineShares(betas...)
	if err != nil {
		return
	}
	decrypted = new(big.Int).Add(decrypt, shares[0].Alpha)
	decrypted.Mod(decrypted, l.PK.N)
	return
}

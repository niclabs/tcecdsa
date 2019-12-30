package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

var one = big.NewInt(1)

type EncryptedL1 struct {
	Alpha, Beta *big.Int
	Proofs      []tcpaillier.ZKProof
}

type DecryptedShareL1 struct {
	Alpha *big.Int
	Beta  *tcpaillier.DecryptionShare
}

func (L1 *EncryptedL1) Verify(pk *tcpaillier.PubKey) error {
	for _, proof := range L1.Proofs {
		if err := proof.Verify(pk); err != nil {
			return err
		}
	}
	return nil
}

func (L1 *DecryptedShareL1) Verify(pk *tcpaillier.PubKey) error {
	return L1.Beta.Verify(pk)
}

func (l *Paillier) AddL1(cList ...*EncryptedL1) (sum *EncryptedL1, err error) {
	if len(cList) == 0 {
		err = fmt.Errorf("empty encrypted list")
		return
	}
	betaSum := cList[0].Beta
	alphaSum := new(big.Int).Set(cList[0].Alpha)
	proofs := make([]tcpaillier.ZKProof, 0)
	for i := 1; i < len(cList); i++ {
		c := cList[i]
		betaSum, err = l.PubKey.Add(betaSum, c.Beta)
		if err != nil {
			return
		}
		alphaSum = alphaSum.Add(alphaSum, c.Alpha)
		proofs = append(proofs, c.Proofs...)
	}

	sum = &EncryptedL1{
		Alpha:  alphaSum,
		Beta:   betaSum,
		Proofs: proofs,
	}
	return
}

func (l *Paillier) Mul(c1, c2 *EncryptedL1) (mul *EncryptedL2, err error) {
	alpha1Alpha2 := new(big.Int).Mul(c1.Alpha, c2.Alpha)
	alpha1Alpha2.Mod(alpha1Alpha2, l.PubKey.N)
	encAlpha1Alpha2, encProof, err := l.PubKey.EncryptFixed(alpha1Alpha2, one)
	if err != nil {
		return
	}
	alpha2Beta1, mulProof1, err := l.PubKey.Multiply(c1.Beta, c2.Alpha)
	if err != nil {
		return
	}
	alpha1Beta2, mulProof2, err := l.PubKey.Multiply(c2.Beta, c1.Alpha)
	if err != nil {
		return
	}
	newAlpha, err := l.PubKey.Add(encAlpha1Alpha2, alpha2Beta1, alpha1Beta2)
	if err != nil {
		return
	}
	mul = &EncryptedL2{
		Alpha:  newAlpha,
		Betas:  make([]*Betas, 0),
		Proofs: make([]tcpaillier.ZKProof, 0),
	}
	mul.Proofs = append(mul.Proofs, mulProof1, mulProof2, encProof)
	mul.Betas = append(mul.Betas, &Betas{
		Beta1: new(big.Int).Set(c1.Beta),
		Beta2: new(big.Int).Set(c2.Beta),
	})
	return
}

func (l *Paillier) MulConstL1(c *EncryptedL1, cons *big.Int) (mul *EncryptedL1, err error) {
	mulBeta, proof, err := l.PubKey.Multiply(c.Beta, cons)
	if err != nil {
		return
	}
	mulAlpha := new(big.Int).Mul(c.Alpha, cons)
	mul = &EncryptedL1{
		Alpha:  mulAlpha,
		Beta:   mulBeta,
		Proofs: make([]tcpaillier.ZKProof, 0),
	}
	mul.Proofs = append(mul.Proofs, proof)
	return
}

func (l *Paillier) PartialDecryptL1(key *tcpaillier.KeyShare, c *EncryptedL1) (share *DecryptedShareL1, err error) {
	partialDecryptBeta, err := key.DecryptProof(c.Beta)
	if err != nil {
		return
	}
	share = &DecryptedShareL1{
		Alpha: c.Alpha,
		Beta:  partialDecryptBeta,
	}
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
	decrypt, err := l.PubKey.CombineShares(betas...)
	if err != nil {
		return
	}
	decrypted = new(big.Int).Add(decrypt, shares[0].Alpha)
	decrypted.Mod(decrypted, l.PubKey.N)
	return
}

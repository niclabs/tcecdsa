package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type EncryptedL2 struct {
	Alpha *big.Int
	Betas []*Betas
}

type DecryptedShareL2 struct {
	Alpha *tcpaillier.DecryptionShare
	Betas []*DecryptedShareBetas
}

type Betas struct {
	Beta1, Beta2 *big.Int
}

type DecryptedShareBetas struct {
	Beta1, Beta2 *tcpaillier.DecryptionShare
}

type DecryptedShare struct {
	Share  tcpaillier.DecryptionShare
	Proofs []tcpaillier.ZKProof
}

func (L2 *EncryptedL2) Clone() *EncryptedL2 {
	betas := make([]*Betas, 0)
	for _, beta := range L2.Betas {
		betas = append(betas, &Betas{
			Beta1: new(big.Int).Set(beta.Beta1),
			Beta2: new(big.Int).Set(beta.Beta2),
		})
	}
	return &EncryptedL2{
		Alpha: new(big.Int).Set(L2.Alpha),
		Betas: betas,
	}

}

func (l *Paillier) AddL2(cList ...*EncryptedL2) (sum *EncryptedL2, err error) {
	if len(cList) == 0 {
		err = fmt.Errorf("empty encrypted list")
		return
	}
	alphas := make([]*big.Int, 0)
	betas := make([]*Betas, 0)
	for i := 0; i < len(cList); i++ {
		c := cList[i]
		alphas = append(alphas, c.Alpha)
		if err != nil {
			return
		}
		for _, beta := range c.Betas {
			betas = append(betas, &Betas{
				Beta1: new(big.Int).Set(beta.Beta1),
				Beta2: new(big.Int).Set(beta.Beta2),
			})
		}
	}
	alphaSum, err := l.PK.Add(alphas...)
	if err != nil {
		return
	}
	sum = &EncryptedL2{
		Alpha: alphaSum,
		Betas: betas,
	}
	return

}

func (l *Paillier) MulConstL2(c *EncryptedL2, cons *big.Int) (mul *EncryptedL2, zk ZKProof, err error) {
	mulAlpha, alphaZK, err := l.PK.Multiply(c.Alpha, cons)
	if err != nil {
		return
	}
	mul = &EncryptedL2{
		Alpha: mulAlpha,
		Betas: make([]*Betas, 0),
	}
	zkp := &EncryptedL2ZK{
		alpha: alphaZK,
		betas: make([]tcpaillier.ZKProof, 0),
	}
	for _, betaPair := range c.Betas {
		mulBeta1, zkpBeta, err2 := l.PK.Multiply(betaPair.Beta1, cons)
		if err2 != nil {
			err = err2
			return
		}
		mul.Betas = append(mul.Betas, &Betas{
			Beta1: mulBeta1,
			Beta2: new(big.Int).Set(betaPair.Beta2),
		})
		zkp.betas = append(zkp.betas, zkpBeta)
	}
	zk = zkp
	return
}

func (l *Paillier) PartialDecryptL2(key *tcpaillier.KeyShare, c *EncryptedL2) (share *DecryptedShareL2, zk ZKProof, err error) {
	decAlpha, zkpAlpha, err := key.Decrypt(c.Alpha)
	if err != nil {
		return
	}
	zkp := &DecryptedShareL2ZK{
		alpha: zkpAlpha,
		betas: make([]*betasZK, 0),
	}
	share = &DecryptedShareL2{
		Alpha: decAlpha,
		Betas: make([]*DecryptedShareBetas, 0),
	}
	for _, beta := range c.Betas {
		dsBeta1, zkpBeta1, err2 := key.Decrypt(beta.Beta1)
		if err2 != nil {
			err = err2
			return
		}
		dsBeta2, zkpBeta2, err2 := key.Decrypt(beta.Beta2)
		if err2 != nil {
			err = err2
			return
		}
		share.Betas = append(share.Betas, &DecryptedShareBetas{
			Beta1: dsBeta1,
			Beta2: dsBeta2,
		})
		zkp.betas = append(zkp.betas, &betasZK{
			beta1: zkpBeta1,
			beta2: zkpBeta2,
		})

	}
	zk = zkp
	return
}

func (l *Paillier) CombineSharesL2(shares ...*DecryptedShareL2) (decrypted *big.Int, err error) {
	if len(shares) == 0 {
		err = fmt.Errorf("empty share list")
		return
	}
	lenBetas := len(shares[0].Betas)
	alphaShares := make([]*tcpaillier.DecryptionShare, 0)

	for i, share := range shares {
		alphaShares = append(alphaShares, share.Alpha)
		// Check if all betas have the same length and alpha
		if len(share.Betas) != lenBetas {
			err = fmt.Errorf("beta length on share %d (%d) is different to the first (%d)", i, len(share.Betas), lenBetas)
			return
		}
	}
	// Decrypt each beta
	decryptedBetas := make([]*Betas, 0)
	for i := 0; i < lenBetas; i++ {
		beta1Shares := make([]*tcpaillier.DecryptionShare, 0)
		beta2Shares := make([]*tcpaillier.DecryptionShare, 0)
		for j := 0; j < len(shares); j++ {
			beta1Shares = append(beta1Shares, shares[j].Betas[i].Beta1)
			beta2Shares = append(beta2Shares, shares[j].Betas[i].Beta2)
		}
		decryptedBeta1, err2 := l.PK.CombineShares(beta1Shares...)
		if err2 != nil {
			err = err2
			return
		}
		decryptedBeta2, err2 := l.PK.CombineShares(beta2Shares...)
		if err2 != nil {
			err = err2
			return
		}
		decryptedBetas = append(decryptedBetas, &Betas{
			Beta1: decryptedBeta1,
			Beta2: decryptedBeta2,
		})
	}

	decrypted, err = l.PK.CombineShares(alphaShares...)
	if err != nil {
		return
	}
	for _, beta := range decryptedBetas {
		mulBeta := new(big.Int).Mul(beta.Beta1, beta.Beta2)
		decrypted.Add(decrypted, mulBeta)
		decrypted.Mod(decrypted, l.PK.N)
	}
	return
}

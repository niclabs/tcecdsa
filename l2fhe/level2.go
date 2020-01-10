package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

// EncryptedL2 represents a Level-2 Encrypted value.
type EncryptedL2 struct {
	Alpha *big.Int
	Betas []*Betas
}

// DecryptedShareL2 represents a Level-2 Decrypted share.
type DecryptedShareL2 struct {
	Alpha *tcpaillier.DecryptionShare
	Betas []*DecryptedShareBetas
}

// Betas groups two beta values together.
type Betas struct {
	Beta1, Beta2 *big.Int
}

// DecryptedShareBetas groups two beta decryption shares together.
type DecryptedShareBetas struct {
	Beta1, Beta2 *tcpaillier.DecryptionShare
}

// Clone clones an EncryptedL2 value.
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

// AddL2 adds a list of Encrypted Level-2 values and returns its encrypted sum.
func (l *PubKey) AddL2(cList ...*EncryptedL2) (sum *EncryptedL2, err error) {
	if len(cList) == 0 {
		err = fmt.Errorf("empty encrypted list")
		return
	}
	alphas := make([]*big.Int, 0)
	betas := make([]*Betas, 0)
	for i := 0; i < len(cList); i++ {
		c := cList[i]
		alphas = append(alphas, c.Alpha)
		for _, beta := range c.Betas {
			betas = append(betas, &Betas{
				Beta1: new(big.Int).Set(beta.Beta1),
				Beta2: new(big.Int).Set(beta.Beta2),
			})
		}
	}
	alphaSum, err := l.Paillier.Add(alphas...)
	if err != nil {
		return
	}
	sum = &EncryptedL2{
		Alpha: alphaSum,
		Betas: betas,
	}
	return

}

// MulConstL2 multiplies an Encrypted Level-2 value by a constant.
// The encryption is deterministic.
// TODO: check if we can use the normal zkproofs to create a zkproof for this case. Meanwhile, we have no ZKProofs.
func (l *PubKey) MulConstL2(c *EncryptedL2, cons *big.Int) (mul *EncryptedL2, err error) {
	mulAlpha, err := l.Paillier.MultiplyFixed(c.Alpha, cons, one)
	if err != nil {
		return
	}
	mul = &EncryptedL2{
		Alpha: mulAlpha,
		Betas: make([]*Betas, 0),
	}

	for _, betaPair := range c.Betas {
		mulBeta1, err2 := l.Paillier.MultiplyFixed(betaPair.Beta1, cons, one)
		if err2 != nil {
			err = err2
			return
		}
		mul.Betas = append(mul.Betas, &Betas{
			Beta1: mulBeta1,
			Beta2: new(big.Int).Set(betaPair.Beta2),
		})
	}
	return
}

// PartialDecryptL2 decrypts partially an encrypted Level-2 value using a given key share. It returns the decrypted
// share and a ZKProof over the encrypted value.
func (l *PubKey) PartialDecryptL2(key *tcpaillier.KeyShare, c *EncryptedL2) (share *DecryptedShareL2, zk *DecryptedShareL2ZK, err error) {
	decAlpha, zkpAlpha, err := key.PartialDecryptWithProof(c.Alpha)
	if err != nil {
		return
	}
	zk = &DecryptedShareL2ZK{
		alpha: zkpAlpha,
		betas: make([]*betasZK, 0),
	}
	share = &DecryptedShareL2{
		Alpha: decAlpha,
		Betas: make([]*DecryptedShareBetas, 0),
	}
	for _, beta := range c.Betas {
		dsBeta1, zkpBeta1, err2 := key.PartialDecryptWithProof(beta.Beta1)
		if err2 != nil {
			err = err2
			return
		}
		dsBeta2, zkpBeta2, err2 := key.PartialDecryptWithProof(beta.Beta2)
		if err2 != nil {
			err = err2
			return
		}
		share.Betas = append(share.Betas, &DecryptedShareBetas{
			Beta1: dsBeta1,
			Beta2: dsBeta2,
		})
		zk.betas = append(zk.betas, &betasZK{
			beta1: zkpBeta1,
			beta2: zkpBeta2,
		})

	}
	return
}

// CombineSharesL2 joins a list of decryption shares, returning the decrypted value.
func (l *PubKey) CombineSharesL2(shares ...*DecryptedShareL2) (decrypted *big.Int, err error) {
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
	// PartialDecryptWithProof each beta
	decryptedBetas := make([]*Betas, 0)
	for i := 0; i < lenBetas; i++ {
		beta1Shares := make([]*tcpaillier.DecryptionShare, 0)
		beta2Shares := make([]*tcpaillier.DecryptionShare, 0)
		for j := 0; j < len(shares); j++ {
			beta1Shares = append(beta1Shares, shares[j].Betas[i].Beta1)
			beta2Shares = append(beta2Shares, shares[j].Betas[i].Beta2)
		}
		decryptedBeta1, err2 := l.Paillier.CombineShares(beta1Shares...)
		if err2 != nil {
			err = err2
			return
		}
		decryptedBeta2, err2 := l.Paillier.CombineShares(beta2Shares...)
		if err2 != nil {
			err = err2
			return
		}
		decryptedBetas = append(decryptedBetas, &Betas{
			Beta1: decryptedBeta1,
			Beta2: decryptedBeta2,
		})
	}

	decrypted, err = l.Paillier.CombineShares(alphaShares...)
	if err != nil {
		return
	}
	for _, beta := range decryptedBetas {
		mulBeta := new(big.Int).Mul(beta.Beta1, beta.Beta2)
		decrypted.Add(decrypted, mulBeta)
		decrypted.Mod(decrypted, l.Paillier.N)
	}
	return
}

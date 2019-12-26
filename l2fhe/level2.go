package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type EncryptedL2 struct {
	Alpha  *big.Int
	Betas  []*Betas
	Proofs []tcpaillier.ZKProof
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

func (L2 *EncryptedL2) Verify(pk *tcpaillier.PubKey) error {
	for _, proof := range L2.Proofs {
		if err := proof.Verify(pk); err != nil {
			return err
		}
	}
	return nil
}

func (L2 *DecryptedShareL2) Verify(pk *tcpaillier.PubKey) error {
	for _, beta := range L2.Betas {
		if err := beta.Beta1.Verify(pk); err != nil {
			return err
		}
		if err := beta.Beta2.Verify(pk); err != nil {
			return err
		}
	}
	return nil
}

func (l *L2TCPaillier) AddL2(cList ...*EncryptedL2) (sum *EncryptedL2, err error) {
	if len(cList) == 0 {
		err = fmt.Errorf("empty encrypted list")
		return
	}
	alphaSum := new(big.Int)
	betas := make([]*Betas, 0)
	betas = append(betas, &Betas{})
	proofs := make([]tcpaillier.ZKProof, 0)
	for i := 0; i < len(cList); i++ {
		c := cList[i]
		alphaSum.Add(alphaSum, c.Alpha)
		for _, beta := range c.Betas {
			betas = append(betas, &Betas{
				Beta1: new(big.Int).Set(beta.Beta1),
				Beta2: new(big.Int).Set(beta.Beta2),
			})
		}
		for _, proof := range c.Proofs {
			proofs = append(proofs, proof)
		}
	}
	sum = &EncryptedL2{
		Alpha:  alphaSum,
		Betas:  betas,
		Proofs: proofs,
	}
	return

}

func (l *L2TCPaillier) MulConstL2(c *EncryptedL2, cons *big.Int) (mul *EncryptedL2, err error) {
	mulAlpha := new(big.Int).Mul(c.Alpha, cons)
	mul = &EncryptedL2{
		Alpha:  mulAlpha,
		Betas:  make([]*Betas, 0),
		Proofs: make([]tcpaillier.ZKProof, 0),
	}
	for _, betaPair := range c.Betas {
		mulBeta1, zkp1, err2 := l.PubKey.Multiply(betaPair.Beta1, cons)
		if err2 != nil {
			err = err2
			return
		}
		mul.Betas = append(mul.Betas, &Betas{
			Beta1: mulBeta1,
			Beta2: new(big.Int).Set(betaPair.Beta2),
		})
		mul.Proofs = append(mul.Proofs, zkp1)
	}
	return
}

func (l *L2TCPaillier) PartialDecryptL2(key *tcpaillier.KeyShare, c *EncryptedL2) (share *DecryptedShareL2, err error) {
	decAlpha, err := key.DecryptProof(c.Alpha)
	if err != nil {
		return
	}
	share = &DecryptedShareL2{
		Alpha: decAlpha,
		Betas: make([]*DecryptedShareBetas, 0),
	}
	for _, beta := range c.Betas {
		dsBeta1, err2 := key.DecryptProof(beta.Beta1)
		if err2 != nil {
			err = err2
			return
		}
		dsBeta2, err2 := key.DecryptProof(beta.Beta2)
		if err2 != nil {
			err = err2
			return
		}
		share.Betas = append(share.Betas, &DecryptedShareBetas{
			Beta1: dsBeta1,
			Beta2: dsBeta2,
		})
	}
	return
}

func (l *L2TCPaillier) CombineSharesL2(shares ...*DecryptedShareL2) (decrypted []byte, err error) {
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
		decryptedBeta1, err2 := l.PubKey.CombineShares(beta1Shares...)
		if err2 != nil {
			err = err2
			return
		}
		decryptedBeta2, err2 := l.PubKey.CombineShares(beta2Shares...)
		if err2 != nil {
			err = err2
			return
		}
		decryptedBetas = append(decryptedBetas, &Betas{
			Beta1: new(big.Int).SetBytes(decryptedBeta1),
			Beta2: new(big.Int).SetBytes(decryptedBeta2),
		})
	}

	decryptAlpha, err := l.PubKey.CombineShares(alphaShares...)
	decryptBig := new(big.Int).SetBytes(decryptAlpha)
	if err != nil {
		return
	}
	for _, beta := range decryptedBetas {
		mulBeta := new(big.Int).Mul(beta.Beta1, beta.Beta2)
		decryptBig.Add(decryptBig, mulBeta)
	}
	decrypted = decryptBig.Bytes()
	return
}

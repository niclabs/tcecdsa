package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type ZKProof interface {
	Verify(*Paillier, ...interface{}) error
}

type EncryptedL1ZK struct {
	beta tcpaillier.ZKProof
}

type DecryptedShareL1ZK struct {
	beta tcpaillier.ZKProof
}

type EncryptedL2ZK struct {
	alpha tcpaillier.ZKProof
	betas []tcpaillier.ZKProof
}

type DecryptedShareL2ZK struct {
	alpha tcpaillier.ZKProof
	betas []*betasZK
}

type betasZK struct {
	beta1, beta2 tcpaillier.ZKProof
}

type MulZK struct {
	a1a2, a2b1, a1b2                *big.Int
	a1a2Proof, a2b1Proof, a1b2Proof tcpaillier.ZKProof
}

func (zk *EncryptedL1ZK) Verify(pk *Paillier, vals ...interface{}) error {

	if len(vals) != 1 {
		return fmt.Errorf("the extra value for verification should be only one")
	}
	c, ok := vals[0].(*EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1")
	}
	return zk.beta.Verify(pk.PK, c.Beta)
}

func (zk *DecryptedShareL1ZK) Verify(pk *Paillier, vals ...interface{}) error {

	if len(vals) != 2 {
		return fmt.Errorf("decryption share verification requires two values")
	}
	c, ok := vals[0].(*EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1 as first argument")
	}
	ci, ok := vals[1].(*DecryptedShareL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a DecryptedShareL1 as second argument")
	}
	return zk.beta.Verify(pk.PK, c.Beta, ci.Beta)
}

func (zk *EncryptedL2ZK) Verify(pk *Paillier, vals ...interface{}) error {

	if len(vals) != 1 {
		return fmt.Errorf("the extra value for verification should be only one")
	}
	c, ok := vals[0].(*EncryptedL2)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL2")
	}
	if len(zk.betas) != len(c.Betas) {
		return fmt.Errorf("zkproof array length is distinct from beta array length")
	}
	if err := zk.alpha.Verify(pk.PK, c.Alpha); err != nil {
		return err
	}
	for i, beta := range zk.betas {
		if err := beta.Verify(pk.PK, c.Betas[i].Beta1); err != nil {
			return err
		}
	}
	return nil
}

func (zk *DecryptedShareL2ZK) Verify(pk *Paillier, vals ...interface{}) error {

	if len(vals) != 2 {
		return fmt.Errorf("decryption share verification requires two values")
	}
	c, ok := vals[0].(*EncryptedL2)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL2 as first argument")
	}
	ci, ok := vals[1].(*DecryptedShareL2)
	if !ok {
		return fmt.Errorf("decryption share verification requires a DecryptedShareL2 as second argument")
	}
	if len(zk.betas) != len(ci.Betas) {
		return fmt.Errorf("zkproof array length is distinct from decrypted share betaPair array length")
	}
	if len(zk.betas) != len(c.Betas) {
		return fmt.Errorf("zkproof array length is distinct from encrypted betaPair array length")
	}
	if err := zk.alpha.Verify(pk.PK, c.Alpha, ci.Alpha); err != nil {
		return err
	}
	for i, betaPair := range zk.betas {
		if err := betaPair.beta1.Verify(pk.PK, c.Betas[i].Beta1, ci.Betas[i].Beta1); err != nil {
			return err
		}
		if err := betaPair.beta2.Verify(pk.PK, c.Betas[i].Beta2, ci.Betas[i].Beta2); err != nil {
			return err
		}
	}
	return nil
}

func (zk *MulZK) Verify(pk *Paillier, _ ...interface{}) error {
	if err := zk.a1a2Proof.Verify(pk.PK, zk.a1a2); err != nil {
		return err
	}
	if err := zk.a2b1Proof.Verify(pk.PK, zk.a2b1); err != nil {
		return err
	}
	if err := zk.a1b2Proof.Verify(pk.PK, zk.a1b2); err != nil {
		return err
	}
	return nil
}

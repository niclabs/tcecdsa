package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
)


// EncryptedL1ZK represents a Zero Knowledge Proof over an Encrypted Level-1 FHE value.
type EncryptedL1ZK struct {
	beta tcpaillier.ZKProof
}

// EncryptedL1ZK represents a Zero Knowledge Proof over an Partially Decrypted Level-1 FHE value.
type DecryptedShareL1ZK struct {
	beta tcpaillier.ZKProof
}

// EncryptedL2ZK represents a Zero Knowledge Proof over an Encrypted Level-2 FHE value.
type EncryptedL2ZK struct {
	alpha tcpaillier.ZKProof
	betas []tcpaillier.ZKProof
}

// EncryptedL2ZK represents a Zero Knowledge Proof over an Partially Decrypted Level-2 FHE value.
type DecryptedShareL2ZK struct {
	alpha tcpaillier.ZKProof
	betas []*betasZK
}

type betasZK struct {
	beta1, beta2 tcpaillier.ZKProof
}

func (zk *EncryptedL1ZK) Verify(pk *tcpaillier.PubKey, vals ...interface{}) error {

	if len(vals) != 1 {
		return fmt.Errorf("the extra value for verification should be only one")
	}
	c, ok := vals[0].(*EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1")
	}
	// Create E(m) = E(alpha) + E(b) = E(m-b) + E(b) from c
	encM, err := c.ToPaillier(pk)
	if err != nil {
		return err
	}
	return zk.beta.Verify(pk, encM)
}


func (zk *DecryptedShareL1ZK) Verify(pk *tcpaillier.PubKey, vals ...interface{}) error {

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
	return zk.beta.Verify(pk, c.Beta, ci.Beta)
}

func (zk *EncryptedL2ZK) Verify(pk *tcpaillier.PubKey, vals ...interface{}) error {

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
	if err := zk.alpha.Verify(pk, c.Alpha); err != nil {
		return err
	}
	for i, beta := range zk.betas {
		if err := beta.Verify(pk, c.Betas[i].Beta1); err != nil {
			return err
		}
	}
	return nil
}

func (zk *DecryptedShareL2ZK) Verify(pk *tcpaillier.PubKey, vals ...interface{}) error {

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
	if err := zk.alpha.Verify(pk, c.Alpha, ci.Alpha); err != nil {
		return err
	}
	for i, betaPair := range zk.betas {
		if err := betaPair.beta1.Verify(pk, c.Betas[i].Beta1, ci.Betas[i].Beta1); err != nil {
			return err
		}
		if err := betaPair.beta2.Verify(pk, c.Betas[i].Beta2, ci.Betas[i].Beta2); err != nil {
			return err
		}
	}
	return nil
}

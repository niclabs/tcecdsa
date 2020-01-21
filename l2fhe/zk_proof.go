package l2fhe

import (
	"fmt"
	"github.com/niclabs/tcpaillier"
)

// EncryptedL1ZK represents a Zero Knowledge Proof over an Encrypted Level-1 FHE value.
type EncryptedL1ZK struct {
	Beta *tcpaillier.EncryptZK
}

// DecryptedShareL1ZK represents a Zero Knowledge Proof over an Partially Decrypted Level-1 FHE value.
type DecryptedShareL1ZK struct {
	Beta *tcpaillier.DecryptShareZK
}

// EncryptedL2ZK represents a Zero Knowledge Proof over an Encrypted Level-2 FHE value.
type EncryptedL2ZK struct {
	Alpha *tcpaillier.EncryptZK
	Betas []*tcpaillier.EncryptZK
}

// DecryptedShareL2ZK represents a Zero Knowledge Proof over an Partially Decrypted Level-2 FHE value.
type DecryptedShareL2ZK struct {
	Alpha *tcpaillier.DecryptShareZK
	Betas []*BetasZK
}

type BetasZK struct {
	Beta1, Beta2 *tcpaillier.DecryptShareZK
}

// Verify verifies a ZKProof of EncryptedL1ZK type. It receives the public key and 1 argument, representing
// the value encrypted.
func (zk *EncryptedL1ZK) Verify(pk *tcpaillier.PubKey, vals ...interface{}) error {

	if len(vals) != 1 {
		return fmt.Errorf("the extra value for verification should be only one")
	}
	c, ok := vals[0].(*EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1")
	}
	// Create E(m) = E(Alpha) + E(b) = E(m-b) + E(b) from c
	encM, err := c.ToPaillier(pk)
	if err != nil {
		return err
	}
	return zk.Beta.Verify(pk, encM)
}

// Verify verifies a ZKProof of DecryptedShareL1ZK type. It receives the public key and 2 arguments, representing
// the value encrypted and the decryption share.
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
	return zk.Beta.Verify(pk, c.Beta, ci.Beta)
}

// Verify verifies a ZKProof of EncryptedL2ZK type. It receives the public key and 1 argument, representing
// the value encrypted.
func (zk *EncryptedL2ZK) Verify(pk *tcpaillier.PubKey, vals ...interface{}) error {

	if len(vals) != 1 {
		return fmt.Errorf("the extra value for verification should be only one")
	}
	c, ok := vals[0].(*EncryptedL2)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL2")
	}
	if len(zk.Betas) != len(c.Betas) {
		return fmt.Errorf("zkproof array length is distinct from Beta array length")
	}
	if err := zk.Alpha.Verify(pk, c.Alpha); err != nil {
		return err
	}
	for i, beta := range zk.Betas {
		if err := beta.Verify(pk, c.Betas[i].Beta1); err != nil {
			return err
		}
	}
	return nil
}

// Verify verifies a ZKProof of DecryptedShareL2ZK type. It receives the public key and 2 arguments, representing
// the value encrypted and the decryption share.
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
	if len(zk.Betas) != len(ci.Betas) {
		return fmt.Errorf("zkproof array length is distinct from decrypted share betaPair array length")
	}
	if len(zk.Betas) != len(c.Betas) {
		return fmt.Errorf("zkproof array length is distinct from encrypted betaPair array length")
	}
	if err := zk.Alpha.Verify(pk, c.Alpha, ci.Alpha); err != nil {
		return err
	}
	for i, betaPair := range zk.Betas {
		if err := betaPair.Beta1.Verify(pk, c.Betas[i].Beta1, ci.Betas[i].Beta1); err != nil {
			return err
		}
		if err := betaPair.Beta2.Verify(pk, c.Betas[i].Beta2, ci.Betas[i].Beta2); err != nil {
			return err
		}
	}
	return nil
}

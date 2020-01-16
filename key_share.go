package tcecdsa

import (
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

// KeyShare represents a "piece" of the key held by a participant of the distributed protocol.
type KeyShare struct {
	Index         uint8                // Participant Index
	Alpha         *l2fhe.EncryptedL1   // Encrypted private Key
	Y             *Point               // Public Key
	PaillierShare *tcpaillier.KeyShare // Paillier Key share, used for partial decryption
}

// Init generates the needed initial parameters and creates the KeyInitMessage that needs to be
// broadcasted to other participants.
func (p *KeyShare) Init(meta *KeyMeta) (msg *KeyInitMessage, err error) {
	var r *big.Int
	xi, err := RandomFieldElement(meta.Curve, meta.RandomSource())
	if err != nil {
		return
	}
	yi := NewZero().BaseMul(meta.Curve, xi)
	alphai, r, err := meta.Encrypt(xi)
	if err != nil {
		return
	}
	zkp, err := newKeyGenZKProof(meta, xi, yi, alphai, r)
	if err != nil {
		return
	}
	msg = &KeyInitMessage{
		AlphaI: alphai,
		Yi:     yi,
		Proof:  zkp,
	}
	return
}

// SetKey sets the key to a keyshare based on the messages of other nodes.
// It defines the Alpha (encrypted private key) and Y (public key) values.
// It returns an error if it cannot join the signatures.
func (p *KeyShare) SetKey(meta *KeyMeta, msgs KeyInitMessageList) error {
	alpha, g, err := msgs.Join(meta)
	if err != nil {
		return err
	}
	p.Alpha = alpha
	p.Y = g
	return nil
}

// NewSigSession creates a new signing session, related to a specific non-empty document.
// It returns the new signing session and the hashed document, using the hash function defined in keyMeta.
// The error returned on this function could only be related to the hash encryption.
func (p *KeyShare) NewSigSession(meta *KeyMeta, h []byte) (state *SigSession, err error) {
	if len(h) == 0 {
		err = fmt.Errorf("empty hash")
		return
	}
	hInt := HashToInt(h, meta.Curve)
	encM, err := meta.EncryptFixedB(hInt, one, one)
	if err != nil {
		return
	}
	state = &SigSession{
		share:  p,
		meta:   meta,
		status: NotInited,
		m:      h,
		encM:   encM,
	}
	return
}

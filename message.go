package tcecdsa

import (
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

// KeyInitMessage defines a message sent on key generation
type KeyInitMessage struct {
	AlphaI *l2fhe.EncryptedL1 // Encrypted private key share by the node
	Yi     *Point             // Public key share by the node
	Proof  *KeyGenZKProof     // ZKProof that the value in AlphaI is a valid private key share
}

// KeyInitMessageList represents a list of KeyInitMessage
type KeyInitMessageList []*KeyInitMessage

// Round1Message defines a message sent on signature Initialization (Round1 on this implementation)
type Round1Message struct {
	Ri         *Point             // Random point related to the signing process
	Ui, Vi, Wi *l2fhe.EncryptedL1 // Encrypted u, V and W shares
	Proof      *SigZKProof        // ZLProof that the values encrypted are valid
}

// Round1MessageList represents a list of Round1Message
type Round1MessageList []*Round1Message

// Round2Message defines a message sent on Round 2
type Round2Message struct {
	PDZ   *l2fhe.DecryptedShareL2 // z Decrypt share.
	Proof tcpaillier.ZKProof      // Proof that PDZ is a partial decryption of z
}

// Round2MessageList represents a list of Round2Message
type Round2MessageList []*Round2Message

// Round3Message defines a message sent on Round 3
type Round3Message struct {
	PDSigma *l2fhe.DecryptedShareL2 // sigma Decrypt share.
	Proof   tcpaillier.ZKProof      // Proof that PDSigma is a partial decryption of sigma
}

// Round3MessageList represents a list of Round3Message
type Round3MessageList []*Round3Message

// Join joins a list of KeyInitMessages and returns the encrypted public key and private keys.
func (msgs KeyInitMessageList) Join(meta *KeyMeta) (alpha *l2fhe.EncryptedL1, y *Point, err error) {
	if len(msgs) != int(meta.Paillier.L) {
		err = fmt.Errorf("number of messages must be equal to participants number L (%d)", meta.Paillier.L)
		return
	}
	alphaIList := make([]*l2fhe.EncryptedL1, 0)
	yiList := make([]*Point, 0)
	for i, msg := range msgs {
		if err = msg.Proof.Verify(meta, msg.Yi, msg.AlphaI); err != nil {
			err = fmt.Errorf("error with zkproof %d: %s", i, err)
			return
		}
		if msg.AlphaI == nil {
			err = fmt.Errorf("alphaI from message %d is nil", i)
			return
		}
		alphaIList = append(alphaIList, msg.AlphaI)
		if msg.Yi == nil {
			err = fmt.Errorf("yi from message %d is nil", i)
			return
		}
		yiList = append(yiList, msg.Yi)
	}
	alpha, err = meta.AddL1(alphaIList...)
	if err != nil {
		return
	}
	y = NewZero().Add(meta.Curve, yiList...)
	return
}

// Join joins a list of Round1Messages and returns the values r, u, v and w.
func (msgs Round1MessageList) Join(meta *KeyMeta) (R *Point, u, v, w *l2fhe.EncryptedL1, err error) {

	k := int(meta.Paillier.K)
	if len(msgs) < k {
		err = fmt.Errorf("length of messages should be at least K")
		return
	}

	rs := make([]*Point, 0)
	us := make([]*l2fhe.EncryptedL1, 0)
	vs := make([]*l2fhe.EncryptedL1, 0)
	ws := make([]*l2fhe.EncryptedL1, 0)

	for _, msg := range msgs {
		if msg.Proof != nil &&
			msg.Ri != nil &&
			msg.Ui != nil &&
			msg.Vi != nil &&
			msg.Wi != nil {
			if err = msg.Proof.Verify(meta, msg.Ri, msg.Ui, msg.Vi, msg.Wi); err == nil {
				rs = append(rs, msg.Ri)
				vs = append(vs, msg.Vi)
				us = append(us, msg.Ui)
				ws = append(ws, msg.Wi)
			} else {
				return
			}
		}
	}

	if len(rs) < k ||
		len(us) < k ||
		len(vs) < k ||
		len(ws) < k {
		err = fmt.Errorf("cannot get minimum number of values needed for protocol")
		return
	}

	rs = rs[:meta.Paillier.K]
	us = us[:meta.Paillier.K]
	vs = vs[:meta.Paillier.K]
	ws = ws[:meta.Paillier.K]

	R = NewZero().Add(meta.Curve, rs...)
	u, err = meta.AddL1(us...)
	if err != nil {
		return
	}
	v, err = meta.AddL1(vs...)
	if err != nil {
		return
	}
	w, err = meta.AddL1(ws...)
	if err != nil {
		return
	}
	return
}

// Join joins a list of Round2Messages and returns the value nu.
// The z value required is to check the ZKProofs.
func (msgs Round2MessageList) Join(meta *KeyMeta, z *l2fhe.EncryptedL2) (nu *big.Int, err error) {
	k := int(meta.Paillier.K)
	if len(msgs) < k {
		err = fmt.Errorf("length of messages should be at least K")
		return
	}
	pdZList := make([]*l2fhe.DecryptedShareL2, 0)
	for _, msg := range msgs {
		if msg.Proof != nil &&
			msg.PDZ != nil {
			if err = msg.Proof.Verify(meta.Paillier, z, msg.PDZ); err == nil {
				pdZList = append(pdZList, msg.PDZ)
			}
		}
	}

	if len(pdZList) < k {
		err = fmt.Errorf("cannot get minimum number of values needed for protocol")
		return
	}

	pdZList = pdZList[:k]
	nu, err = meta.CombineSharesL2(pdZList...)
	if err != nil {
		return
	}
	nu.Mod(nu, meta.Q())
	return
}

// Join joins a list of Round3Messages and returns the value s.
// the sigma value required is to check the ZKProofs.
func (msgs Round3MessageList) Join(meta *KeyMeta, sigma *l2fhe.EncryptedL2) (s *big.Int, err error) {
	k := int(meta.Paillier.K)
	if len(msgs) < k {
		err = fmt.Errorf("length of messages should be at least K")
		return
	}
	pdSigmaList := make([]*l2fhe.DecryptedShareL2, 0)
	for _, msg := range msgs {
		if msg.Proof != nil &&
			msg.PDSigma != nil {
			if err = msg.Proof.Verify(meta.Paillier, sigma, msg.PDSigma); err == nil {
				pdSigmaList = append(pdSigmaList, msg.PDSigma)
			}
		}
	}
	if len(pdSigmaList) < k {
		err = fmt.Errorf("cannot get minimum number of values needed for protocol")
		return
	}
	pdSigmaList = pdSigmaList[:k]
	s, err = meta.CombineSharesL2(pdSigmaList...)
	if err != nil {
		return
	}
	s.Mod(s, meta.Q())
	return
}

package tcecdsa

import (
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type KeyInitMessage struct {
	AlphaI *l2fhe.EncryptedL1
	Yi     *Point
	Proof  *KeyGenZKProof
}
type SigInitMessage struct {
	Ri         *Point
	Ui, Vi, Wi *l2fhe.EncryptedL1
	Proof      *SigZKProof
}

type Round2Message struct {
	Z     *l2fhe.EncryptedL2
	PDZ   *l2fhe.DecryptedShareL2
	Proof tcpaillier.ZKProof
}

type Round3Message struct {
	Sigma   *l2fhe.EncryptedL2
	PDSigma *l2fhe.DecryptedShareL2
	Proof   tcpaillier.ZKProof
}

func (meta *KeyMeta) joinKeyInit(msgs ...*KeyInitMessage) (alpha *l2fhe.EncryptedL1, y *Point, err error) {
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

func (meta *KeyMeta) joinSigInit(msgs ...*SigInitMessage) (R *Point, u, v, w *l2fhe.EncryptedL1, err error) {

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
			if err = msg.Proof.Verify(meta, msg.Ri, msg.Vi, msg.Ui, msg.Wi); err == nil {
				rs = append(rs, msg.Ri)
				vs = append(vs, msg.Vi)
				us = append(us, msg.Ui)
				ws = append(ws, msg.Wi)
			} else {
				fmt.Errorf("%s", err)
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

func (meta *KeyMeta) getNu(msgs ...*Round2Message) (nu *big.Int, err error) {
	if len(msgs) < int(meta.Paillier.K) {
		err = fmt.Errorf("length of messages should be at least K")
		return
	}
	pdZList := make([]*l2fhe.DecryptedShareL2, 0)
	for _, msg := range msgs {
		if msg.Proof != nil &&
			msg.PDZ != nil {
			if err = msg.Proof.Verify(meta.Paillier, msg.Z, msg.PDZ); err == nil {
				pdZList = append(pdZList, msg.PDZ)
			}
		}
	}

	pdZList = pdZList[:meta.Paillier.K]
	nu, err = meta.CombineSharesL2(pdZList...)
	if err != nil {
		return
	}
	nu.Mod(nu, meta.Q())
	return
}

func (meta *KeyMeta) getS(msgs ...*Round3Message) (s *big.Int, err error) {
	if len(msgs) < int(meta.Paillier.K) {
		err = fmt.Errorf("length of messages should be at least K")
		return
	}
	pdSigmaList := make([]*l2fhe.DecryptedShareL2, 0)
	for _, msg := range msgs {
		if msg.Proof != nil &&
			msg.PDSigma != nil {
			if err = msg.Proof.Verify(meta.Paillier, msg.Sigma, msg.PDSigma); err == nil {
				pdSigmaList = append(pdSigmaList, msg.PDSigma)
			}
		}
	}
	pdSigmaList = pdSigmaList[:meta.Paillier.K]
	s, err = meta.CombineSharesL2(pdSigmaList...)
	if err != nil {
		return
	}
	s.Mod(s, meta.Q())
	return
}

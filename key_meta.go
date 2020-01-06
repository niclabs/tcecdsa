package tcecdsa

import (
	"crypto/elliptic"
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"io"
	"math/big"
)

type KeyMeta struct {
	*l2fhe.PubKey
	*ZKProofMeta
	Curve elliptic.Curve
}

// Returns Curve Subfield bitlength
func (meta *KeyMeta) Q() *big.Int {
	return meta.Curve.Params().N
}

func (meta *KeyMeta) RandomSource() io.Reader {
	return meta.Paillier.RandSource
}

func (meta *KeyMeta) G() *Point {
	return &Point{
		X: new(big.Int).Set(meta.Curve.Params().Gx),
		Y: new(big.Int).Set(meta.Curve.Params().Gy),
	}
}

func (meta *KeyMeta) JoinRound1Messages(msgs ...*Round1Message) (R *Point, u, v, w *l2fhe.EncryptedL1, err error) {
	if len(msgs) >= int(meta.Paillier.K) {
		err = fmt.Errorf("length of messages should be at least K")
		return
	}

	rs := make([]*Point, 0)
	us := make([]*l2fhe.EncryptedL1, 0)
	vs := make([]*l2fhe.EncryptedL1, 0)
	ws := make([]*l2fhe.EncryptedL1, 0)
	proofs := make([]*SigZKProof, 0)

	for _, msg := range msgs {
		if msg.Proof != nil &&
			msg.R != nil &&
			msg.U != nil &&
			msg.V != nil &&
			msg.W != nil {
			rs = append(rs, msg.R)
			us = append(us, msg.U)
			vs = append(vs, msg.V)
			ws = append(ws, msg.W)
			proofs = append(proofs, msg.Proof)
		}
	}

	rs = rs[:meta.Paillier.K]
	us = us[:meta.Paillier.K]
	vs = vs[:meta.Paillier.K]
	ws = ws[:meta.Paillier.K]

	for i, proof := range proofs {
		if err = proof.Verify(meta, rs[i], us[i], vs[i], ws[i]); err != nil {
			return
		}
	}
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

package tcecdsa

import (
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type KeyShare struct {
	Index         uint8
	Rho           *big.Int
	Alpha         *l2fhe.EncryptedL1
	Y             *Point
	PaillierShare *tcpaillier.KeyShare
}

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

func (p *KeyShare) SetKey(meta *KeyMeta, msgs ...*KeyInitMessage) error {
	alpha, g, err := meta.joinKeyInit(msgs...)
	if err != nil {
		return err
	}
	p.Alpha = alpha
	p.Y = g
	return nil
}

func (p *KeyShare) NewSigState(meta *KeyMeta, doc []byte) (state *SigState, h []byte, err error) {
	meta.Hash.Reset()
	meta.Hash.Write(doc)
	h = meta.Hash.Sum(nil)
	hInt := HashToInt(h, meta.Curve)
	encM, _, err := meta.Encrypt(hInt)
	if err != nil {
		return
	}
	state = &SigState{
		Share:  p,
		Meta:   meta,
		Status: NotInited,
		M:      h,
		EncM:   encM,
	}
	return
}

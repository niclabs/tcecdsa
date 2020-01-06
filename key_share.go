package tcecdsa

import (
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type KeyShare struct {
	Index         uint8
	Rho           *big.Int
	Exi           *l2fhe.EncryptedL1
	Yi            *Point
	PaillierShare *tcpaillier.KeyShare
}

type Round1Message struct {
	R       *Point
	U, V, W *l2fhe.EncryptedL1
	Proof   *SigZKProof
}

func (p *KeyShare) Init(meta *KeyMeta) (zkp *KeyGenZKProof, err error) {
	var r *big.Int
	xi, err := RandomFieldElement(meta.Curve, meta.RandomSource())
	if err != nil {
		return
	}
	p.Yi = NewZero().BaseMul(meta.Curve, xi)
	p.Exi, r, err = meta.Encrypt(xi)
	if err != nil {
		return
	}
	zkp, err = newKeyGenZKProof(meta, xi, p.Yi, p.Exi, r)
	if err != nil {
		return
	}
	return
}

func (p *KeyShare) ReceivePublicPointShares(meta *KeyMeta, yiList []*Point, xiList []*l2fhe.EncryptedL1, zkproofs []*KeyGenZKProof) (exP *l2fhe.EncryptedL1, yP *Point, err error) {
	if len(xiList) != len(zkproofs) {
		err = fmt.Errorf("zkproof len is not equal to xiList len")
		return
	}
	for i, proof := range zkproofs {
		if err = proof.Verify(meta, xiList[i]); err != nil {
			err = fmt.Errorf("error with zkproof %d: %s", i, err)
			return
		}
	}
	yP = NewZero().Add(meta.Curve, yiList...)
	exP, err = meta.AddL1(xiList...)
	return
}

func (p *KeyShare) Round1(meta *KeyMeta) (msg *Round1Message, err error) {
	// choose rho_i, k_i random from Z_q, and c_i from [-q^6, q^6]
	rho, err := RandomInRange(zero, meta.Q(), meta.RandomSource())
	if err != nil {
		return
	}
	k, err := RandomInRange(zero, meta.Q(), meta.RandomSource())
	if err != nil {
		return
	}
	qToSix := new(big.Int).Exp(meta.Q(), big.NewInt(6), nil)
	minusQToSix := new(big.Int).Neg(qToSix)
	c, err := RandomInRange(minusQToSix, qToSix, meta.RandomSource())
	if err != nil {
		return
	}
	r := NewZero().BaseMul(meta.Curve, k)
	u, randU, err := meta.Encrypt(rho)
	if err != nil {
		return
	}
	v, randV, err := meta.Encrypt(rho)
	if err != nil {
		return
	}
	w, randW, err := meta.Encrypt(rho)
	if err != nil {
		return
	}
	proofParams := &SigZKProofParams{
		eta1:  k,
		eta2:  rho,
		eta3:  c,
		r:     r,
		encW1: v,
		encW2: u,
		encW3: w,
		r1:    randV,
		r2:    randU,
		r3:    randW,
	}
	proof, err := NewSigZKProof(meta, proofParams)

	msg = &Round1Message{
		R:     r,
		U:     u,
		V:     v,
		W:     w,
		Proof: proof,
	}

	return
}

// Round3
func (p *KeyShare) Round2(meta *KeyMeta, R *Point, u, v, w *l2fhe.EncryptedL1, proofs []*SigZKProof) (pdZ *l2fhe.DecryptedShareL2, zkp *l2fhe.DecryptedShareL2ZK, err error) {
	uv, err := meta.Mul(v, u)
	if err != nil {
		return
	}
	qw, err := meta.MulConstL1(w, meta.Q())
	if err != nil {
		return
	}
	qwL2, err := qw.ToL2(meta.PubKey)
	if err != nil {
		return
	}
	z, err := meta.AddL2(uv, qwL2)
	if err != nil {
		return
	}
	pdZ, zkp, err = meta.PartialDecryptL2(p, z)
	return
}

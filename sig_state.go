package tcecdsa

import (
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"math/big"
)

type Status uint8

const (
	NotInited Status = iota
	Round1
	Round2
	Round3
	Finished
	Undefined Status = iota
)

type SigState struct {
	Share  *KeyShare
	Meta   *KeyMeta
	Status Status
	R, S   *big.Int
	Nu     *big.Int
	M      []byte
	EncM   *l2fhe.EncryptedL1
	U      *l2fhe.EncryptedL1
	Sigma  *l2fhe.EncryptedL2
}

// Round1 is Round 1 and 2 in paper
func (state *SigState) Round1() (msg *SigInitMessage, err error) {
	if state.Status != NotInited {
		err = fmt.Errorf("status should be \"Not Inited\" to use this method")
	}
	// choose rho_i, k_i random from Z_q, and c_i from [-q^6, q^6]
	rho, err := RandomInRange(zero, state.Meta.Q(), state.Meta.RandomSource())
	if err != nil {
		return
	}
	k, err := RandomInRange(zero, state.Meta.Q(), state.Meta.RandomSource())
	if err != nil {
		return
	}
	qToSix := new(big.Int).Exp(state.Meta.Q(), big.NewInt(6), nil)
	minusQToSix := new(big.Int).Neg(qToSix)
	c, err := RandomInRange(minusQToSix, qToSix, state.Meta.RandomSource())
	if err != nil {
		return
	}
	r := NewZero().BaseMul(state.Meta.Curve, k)
	u, ru, err := state.Meta.Encrypt(rho)
	if err != nil {
		return
	}
	v, rv, err := state.Meta.Encrypt(k)
	if err != nil {
		return
	}
	w, rw, err := state.Meta.Encrypt(c)
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
		r1:    rv,
		r2:    ru,
		r3:    rw,
	}
	proof, err := NewSigZKProof(state.Meta, proofParams)

	msg = &SigInitMessage{
		Ri:    r,
		Ui:    u,
		Vi:    v,
		Wi:    w,
		Proof: proof,
	}
	state.Status = Round1
	return
}

// Round2 is Round2 in paper.
func (state *SigState) Round2(msgs ...*SigInitMessage) (msg *Round2Message, err error) {
	if state.Status != Round1 {
		err = fmt.Errorf("status should be \"Round1\" to use this method")
	}
	R, u, v, w, err := state.Meta.joinSigInit(msgs...)
	uv, err := state.Meta.Mul(v, u)
	if err != nil {
		return
	}
	qw, err := state.Meta.MulConstL1(w, state.Meta.Q())
	if err != nil {
		return
	}
	qwL2, err := qw.ToL2(state.Meta.PubKey)
	if err != nil {
		return
	}
	z, err := state.Meta.AddL2(uv, qwL2)
	if err != nil {
		return
	}
	pdZ, zkp, err := state.Meta.PartialDecryptL2(state.Share.PaillierShare, z)
	r := R.X
	msg = &Round2Message{
		Z:     z,
		PDZ:   pdZ,
		Proof: zkp,
	}
	state.Status = Round2
	state.U, state.R = u, r
	return
}

// Round3 is Round3 in Paper
func (state *SigState) Round3(msgs ...*Round2Message) (msg *Round3Message, err error) {
	if state.Status != Round2 {
		err = fmt.Errorf("status should be \"Round2\" to use this method")
	}
	nu, err := state.Meta.getNu(msgs...)
	if err != nil {
		return
	}
	psi := new(big.Int).ModInverse(nu, state.Meta.Q())
	vHat, err := state.Meta.MulConstL1(state.U, psi)
	if err != nil {
		return
	}
	rAlpha, err := state.Meta.MulConstL1(state.Share.Alpha, state.R)
	if err != nil {
		return
	}
	rAlphaPlusEncM, err := state.Meta.AddL1(rAlpha, state.EncM)
	if err != nil {
		return
	}
	sigma, err := state.Meta.Mul(rAlphaPlusEncM, vHat)
	if err != nil {
		return
	}
	pdSigma, zkp, err := state.Meta.PartialDecryptL2(state.Share.PaillierShare, sigma)
	if err != nil {
		return
	}
	msg = &Round3Message{
		Sigma:   sigma,
		PDSigma: pdSigma,
		Proof:   zkp,
	}
	state.Nu = nu
	state.Sigma = sigma
	state.Status = Round3
	return
}

// Round4 joins the last values and returns the signature
func (state *SigState) Round4(msgs ...*Round3Message) (r, s *big.Int, err error) {
	if state.Status != Round3 {
		err = fmt.Errorf("status should be \"Round3\" to use this method")
	}
	s, err = state.Meta.getS(msgs...)
	if err != nil {
		return
	}
	r = state.R
	state.S = s
	state.Status = Finished
	return
}

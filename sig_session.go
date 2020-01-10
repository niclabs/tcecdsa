package tcecdsa

import (
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"math/big"
)

// status represents the current state of a SigSession
type Status uint8

const (
	NotInited Status = iota // Session was created
	Round1                  // Session has passed Round 1
	Round2                  // Session has passed Round 2
	Round3                  // Session has passed Round 3
	Finished                // Session is finished.
	Undefined Status = iota
)

// SigSession represents a set of values saved and used by the participants
// to generate an specific signature.
// It is an ephimeral structure and it lives only while the signature is being created.
type SigSession struct {
	status   Status             // Session status
	r, s     *big.Int           // Final signature
	share    *KeyShare          // KeyShare related to the current signing process
	meta     *KeyMeta           // KeyMeta related to the current signing process
	sigma, z *l2fhe.EncryptedL2 // Valqwues needed to check ZKProofs
	m        []byte             // Hashed message
	encM     *l2fhe.EncryptedL1 // Encrypted hashed message
	u        *l2fhe.EncryptedL1 // Value used between rounds 2 and 3 in signing process
}

// Round1 starts the signing process generating a set of random values and the ZKProof of them.
// It represents Round 1 and Round 2 in paper, because our implementation doesn't consider the usage of commits.
func (state *SigSession) Round1() (msg *Round1Message, err error) {
	if state.status != NotInited {
		err = fmt.Errorf("status should be \"Not Inited\" to use this method")
	}
	// choose rho_i, k_i random from Z_q, and c_i from [-q^6, q^6]
	rho, err := RandomInRange(zero, state.meta.Q(), state.meta.RandomSource())
	if err != nil {
		return
	}
	k, err := RandomInRange(zero, state.meta.Q(), state.meta.RandomSource())
	if err != nil {
		return
	}
	qToSix := new(big.Int).Exp(state.meta.Q(), big.NewInt(6), nil)
	ci, err := RandomInRange(zero, qToSix, state.meta.RandomSource())
	if err != nil {
		return
	}
	ri := NewZero().BaseMul(state.meta.Curve, k)
	ui, rui, err := state.meta.Encrypt(rho)
	if err != nil {
		return
	}
	vi, rvi, err := state.meta.Encrypt(k)
	if err != nil {
		return
	}
	wi, rwi, err := state.meta.Encrypt(ci)
	if err != nil {
		return
	}
	proofParams := &SigZKProofParams{
		eta1:     k,
		eta2:     rho,
		eta3:     ci,
		ri:       ri,
		encUi:    ui,
		encVi:    vi,
		encWi:    wi,
		randomUi: rui,
		randomVi: rvi,
		randomWi: rwi,
	}
	proof, err := NewSigZKProof(state.meta, proofParams)

	msg = &Round1Message{
		Ri:    ri,
		Ui:    ui,
		Vi:    vi,
		Wi:    wi,
		Proof: proof,
	}
	state.status = Round1
	return
}

/// Round2 uses the values generated in Round1 to generate r and u, a value that is needed for GetSignature
// It is Round 3 in paper.
func (state *SigSession) Round2(msgs Round1MessageList) (msg *Round2Message, err error) {
	if state.status != Round1 {
		err = fmt.Errorf("status should be \"Round1\" to use this method")
	}
	R, u, v, w, err := msgs.Join(state.meta)
	uv, err := state.meta.Mul(v, u)
	if err != nil {
		return
	}
	qw, err := state.meta.MulConstL1(w, state.meta.Q())
	if err != nil {
		return
	}
	qwL2, err := qw.ToL2(state.meta.PubKey)
	if err != nil {
		return
	}
	z, err := state.meta.AddL2(uv, qwL2)
	if err != nil {
		return
	}

	pdZ, zkp, err := state.meta.PartialDecryptL2(state.share.PaillierShare, z)
	r := R.X

	msg = &Round2Message{
		PDZ:   pdZ,
		Proof: zkp,
	}
	state.z = z
	state.status = Round2
	state.u, state.r = u, r
	return
}

// Round3 joins the partially decrypted z of the last round and generates a partial decryption of sigma.
// It is Round 4 in paper
func (state *SigSession) Round3(msgs Round2MessageList) (msg *Round3Message, err error) {
	if state.status != Round2 {
		err = fmt.Errorf("status should be \"Round2\" to use this method")
	}
	nu, err := msgs.Join(state.meta, state.z)
	if err != nil {
		return
	}
	psi := new(big.Int).ModInverse(nu, state.meta.Q())
	vHat, err := state.meta.MulConstL1(state.u, psi)
	if err != nil {
		return
	}
	rAlpha, err := state.meta.MulConstL1(state.share.Alpha, state.r)
	if err != nil {
		return
	}
	rAlphaPlusEncM, err := state.meta.AddL1(rAlpha, state.encM)
	if err != nil {
		return
	}
	sigma, err := state.meta.Mul(rAlphaPlusEncM, vHat)
	if err != nil {
		return
	}
	pdSigma, zkp, err := state.meta.PartialDecryptL2(state.share.PaillierShare, sigma)
	if err != nil {
		return
	}
	msg = &Round3Message{
		PDSigma: pdSigma,
		Proof:   zkp,
	}
	state.sigma = sigma
	state.status = Round3
	return
}

// GetSignature joins the last values and returns the signature.
// It is described in the paper as the joining process of partially decrypted values.
func (state *SigSession) GetSignature(msgs Round3MessageList) (r, s *big.Int, err error) {
	if state.status == Finished {
		// ri and s already calculated, return them.
		r, s = state.r, state.s
		return
	}
	if state.status != Round3 {
		err = fmt.Errorf("status should be \"Round3\" to use this method")
	}
	s, err = msgs.Join(state.meta, state.sigma)
	if err != nil {
		return
	}
	r = state.r
	state.s = s
	state.status = Finished
	return
}

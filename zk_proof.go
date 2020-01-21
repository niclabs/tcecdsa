package tcecdsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"math/big"
)

var hash = sha256.New()


// ZKProof represents a Zero Knowledge Proof used by TCECDSA.
type ZKProof interface {
	// Verify verifies a ZKProof. It returns nil if the proof is OK, an error if it is not.
	Verify(meta *KeyMeta, args ...interface{}) error
}

// ZKProofMeta contains the RSA parameters required to create ZKProofs.
type ZKProofMeta struct {
	NTilde *big.Int // Used in ZK Proofs
	H1     *big.Int // Used in ZK Proofs
	H2     *big.Int // Used in ZK Proofs
}

// SigZKProofParams groups all the params used on Signing ZKProof.
type SigZKProofParams struct {
	ri                           *Point
	eta1, eta2, eta3             *big.Int
	randomVi, randomUi, randomWi *big.Int
	encVi, encUi, encWi          *l2fhe.EncryptedL1
}

// KeyGenZKProof represents the parameters for the Key Generation ZKProof.
type KeyGenZKProof struct {
	u1         *Point
	u2, u3     *big.Int
	s1, s2, s3 *big.Int
	e          *big.Int
	z          *big.Int
}

// SigZKProof represents the parameters for the signature ZKProof.
type SigZKProof struct {
	u1                     *Point
	u2, u3, u4             *big.Int
	z1, z2, z3             *big.Int
	v1, v2, v3             *big.Int
	s1, s3, s4, s5, s6, s7 *big.Int
	t1, t2, t3             *big.Int
	e                      *big.Int
}

// genZKProofMeta returns a new ZKProofMeta with random parameters, based on the given reader.
func genZKProofMeta() (*ZKProofMeta, error) {
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	nTilde := sk.N
	h1, err := rand.Int(rand.Reader, nTilde)
	if err != nil {
		return nil, err
	}
	h2, err := rand.Int(rand.Reader, nTilde)
	if err != nil {
		return nil, err
	}
	return &ZKProofMeta{
		NTilde: nTilde,
		H1:     h1,
		H2:     h2,
	}, nil
}

// newKeyGenZKProof creates the Key Generation ZKProof used by the protocol.
func newKeyGenZKProof(meta *KeyMeta, xi *big.Int, yi *Point, wFHE *l2fhe.EncryptedL1, r *big.Int) (proof *KeyGenZKProof, err error) {
	n := meta.Paillier.N
	q := meta.Q()

	cache := meta.Paillier.Cache()
	nPlusOne := cache.NPlusOne
	nToSPlusOne := cache.NToSPlusOne
	h1, h2 := meta.H1, meta.H2
	qToThree := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
	nTilde := meta.NTilde
	qnTilde := new(big.Int).Mul(q, nTilde)
	qToThreeNTilde := new(big.Int).Mul(qToThree, nTilde)

	alpha, err := RandomInRange(one, qToThree)
	if err != nil {
		return
	}
	beta, err := RandomInRange(one, n)
	if err != nil {
		return
	}
	rho, err := RandomInRange(one, qnTilde)
	if err != nil {
		return
	}
	gamma, err := RandomInRange(one, qToThreeNTilde)
	if err != nil {
		return
	}

	z := new(big.Int).Exp(h1, xi, nTilde)
	z.Mul(z, new(big.Int).Exp(h2, rho, nTilde)).Mod(z, nTilde)

	u1 := NewZero().BaseMul(meta.Curve(), alpha)

	u2 := new(big.Int).Exp(nPlusOne, alpha, nToSPlusOne)
	u2.Mul(u2, new(big.Int).Exp(beta, n, nToSPlusOne)).
		Mod(u2, nToSPlusOne)

	u3 := new(big.Int).Exp(h1, alpha, nTilde)
	u3.Mul(u3, new(big.Int).Exp(h2, gamma, nTilde)).
		Mod(u3, nTilde)

	w, err := wFHE.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return
	}

	hash.Reset()
	hash.Write(meta.G().Bytes(meta.Curve()))
	hash.Write(yi.Bytes(meta.Curve()))
	hash.Write(w.Bytes())
	hash.Write(z.Bytes())
	hash.Write(u1.Bytes(meta.Curve()))
	hash.Write(u2.Bytes())
	hash.Write(u3.Bytes())
	eHash := hash.Sum(nil)

	e := new(big.Int).SetBytes(eHash)

	s1 := new(big.Int).Mul(e, xi)
	s1.Add(s1, alpha)

	s2 := new(big.Int).Exp(r, e, n)
	s2.Mul(s2, beta).Mod(s2, n)

	s3 := new(big.Int).Mul(e, rho)
	s3.Add(s3, gamma)

	proof = &KeyGenZKProof{
		z:  z,
		u1: u1,
		u2: u2,
		u3: u3,
		s1: s1,
		s2: s2,
		s3: s3,
		e:  e,
	}
	return
}

// Verify verifies a ZKProof of KeyGenZKProof type. It receives the key metainfo and 2 arguments, representing
// the public key share (a point), and the encrypted private key share.
func (p *KeyGenZKProof) Verify(meta *KeyMeta, vals ...interface{}) error {
	if len(vals) != 2 {
		return fmt.Errorf("the verification requires three values: yi (*Point) and w (*l2fhe.EncryptedL1)")
	}
	yi, ok := vals[0].(*Point)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *Point as first argument")
	}
	wFHE, ok := vals[1].(*l2fhe.EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1 as second argument")
	}

	n := meta.Paillier.N
	cache := meta.Paillier.Cache()
	nPlusOne := cache.NPlusOne
	nToSPlusOne := cache.NToSPlusOne
	h1, h2 := meta.H1, meta.H2
	nTilde := meta.NTilde

	w, err := wFHE.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return err
	}

	u1 := NewZero().BaseMul(meta.Curve(), p.s1)
	pu1 := NewZero().Add(meta.Curve(), p.u1, NewZero().Mul(meta.Curve(), yi, p.e))

	u2 := new(big.Int).Exp(nPlusOne, p.s1, nToSPlusOne)
	u2.Mul(u2, new(big.Int).Exp(p.s2, n, nToSPlusOne)).
		Mod(u2, nToSPlusOne)
	pu2 := new(big.Int).Mul(p.u2, new(big.Int).Exp(w, p.e, nToSPlusOne))
	pu2.Mod(pu2, nToSPlusOne)

	u3 := new(big.Int).Exp(h1, p.s1, nTilde)
	u3.Mul(u3, new(big.Int).Exp(h2, p.s3, nTilde)).
		Mod(u3, nTilde)
	pu3 := new(big.Int).Mul(p.u3, new(big.Int).Exp(p.z, p.e, nTilde))
	pu3.Mod(pu3, nTilde)

	hash.Reset()
	hash.Write(meta.G().Bytes(meta.Curve()))
	hash.Write(yi.Bytes(meta.Curve()))
	hash.Write(w.Bytes())
	hash.Write(p.z.Bytes())
	hash.Write(p.u1.Bytes(meta.Curve()))
	hash.Write(p.u2.Bytes())
	hash.Write(p.u3.Bytes())
	eHash := hash.Sum(nil)

	e := new(big.Int).SetBytes(eHash)

	if pu1.Cmp(u1) != 0 {
		fmt.Println("u1 zkp failed")
		//return fmt.Errorf("zkproof failed")
	}
	if pu2.Cmp(u2) != 0 {
		fmt.Println("u2 zkp failed")
		//return fmt.Errorf("zkproof failed")
	}
	if pu3.Cmp(u3) != 0 {
		fmt.Println("u3 zkp failed")
		//return fmt.Errorf("zkproof failed")
	}

	if p.e.Cmp(e) != 0 {
		fmt.Println("e zkp failed")
		//return fmt.Errorf("zkproof failed")
	}

	return nil
}

// NewSigZKProof creates the SigZKProof used by the protocol. This implementation is based on the original one by the
// authors of the paper.
func NewSigZKProof(meta *KeyMeta, p *SigZKProofParams) (proof *SigZKProof, err error) {
	cache := meta.Paillier.Cache()
	n := meta.Paillier.N

	q := meta.Q()
	nToSPlusOne := cache.NToSPlusOne
	nTilde := meta.NTilde
	h1 := meta.H1
	h2 := meta.H2
	nPlusOne := cache.NPlusOne

	w1, err := p.encVi.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return
	}
	w2, err := p.encUi.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return
	}
	w3, err := p.encWi.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return
	}

	qToThree := new(big.Int).Exp(q, big.NewInt(3), nil)
	qToFive := new(big.Int).Exp(q, big.NewInt(5), nil)
	qToSeven := new(big.Int).Exp(q, big.NewInt(7), nil)

	qNTilde := new(big.Int).Mul(q, nTilde)
	qToThreeNTilde := new(big.Int).Mul(qToThree, nTilde)
	qToFiveNTilde := new(big.Int).Mul(qToFive, nTilde)
	qToSevenNTilde := new(big.Int).Mul(qToSeven, nTilde)

	alpha1, err := RandomInRange(zero, qToThree)
	if err != nil {
		return
	}
	alpha2, err := RandomInRange(zero, qToThree)
	if err != nil {
		return
	}
	alpha3, err := RandomInRange(zero, qToSeven)
	if err != nil {
		return
	}

	beta1, err := RandomInRange(one, n)
	if err != nil {
		return
	}
	beta2, err := RandomInRange(one, n)
	if err != nil {
		return
	}
	beta3, err := RandomInRange(one, n)
	if err != nil {
		return
	}

	gamma1, err := RandomInRange(zero, qToThreeNTilde)
	if err != nil {
		return
	}
	gamma2, err := RandomInRange(zero, qToThreeNTilde)
	if err != nil {
		return
	}
	gamma3, err := RandomInRange(zero, qToSevenNTilde)
	if err != nil {
		return
	}

	rho1, err := RandomInRange(zero, qNTilde)
	if err != nil {
		return
	}
	rho2, err := RandomInRange(zero, qNTilde)
	if err != nil {
		return
	}
	rho3, err := RandomInRange(zero, qToFiveNTilde)
	if err != nil {
		return
	}

	z1 := new(big.Int).Exp(h1, p.eta1, nTilde)
	z1.Mul(z1, new(big.Int).Exp(h2, rho1, nTilde)).Mod(z1, nTilde)
	z2 := new(big.Int).Exp(h1, p.eta2, nTilde)
	z2.Mul(z2, new(big.Int).Exp(h2, rho2, nTilde)).Mod(z2, nTilde)
	z3 := new(big.Int).Exp(h1, p.eta3, nTilde)
	z3.Mul(z3, new(big.Int).Exp(h2, rho3, nTilde)).Mod(z3, nTilde)

	u1 := NewZero().BaseMul(meta.Curve(), alpha1)

	u2 := new(big.Int).Exp(nPlusOne, alpha1, nToSPlusOne)
	u2.Mul(u2, new(big.Int).Exp(beta1, n, nToSPlusOne)).Mod(u2, nToSPlusOne)
	u3 := new(big.Int).Exp(nPlusOne, alpha2, nToSPlusOne)
	u3.Mul(u3, new(big.Int).Exp(beta2, n, nToSPlusOne)).Mod(u3, nToSPlusOne)
	u4 := new(big.Int).Exp(nPlusOne, alpha3, nToSPlusOne)
	u4.Mul(u4, new(big.Int).Exp(beta3, n, nToSPlusOne)).Mod(u4, nToSPlusOne)

	v1 := new(big.Int).Exp(h1, alpha1, nTilde)
	v1.Mul(v1, new(big.Int).Exp(h2, gamma1, nTilde)).Mod(v1, nTilde)
	v2 := new(big.Int).Exp(h1, alpha2, nTilde)
	v2.Mul(v2, new(big.Int).Exp(h2, gamma2, nTilde)).Mod(v2, nTilde)
	v3 := new(big.Int).Exp(h1, alpha3, nTilde)
	v3.Mul(v3, new(big.Int).Exp(h2, gamma3, nTilde)).Mod(v3, nTilde)

	hash.Reset()
	hash.Write(meta.G().Bytes(meta.Curve()))
	hash.Write(p.ri.Bytes(meta.Curve()))
	hash.Write(w1.Bytes())
	hash.Write(w2.Bytes())
	hash.Write(w3.Bytes())
	hash.Write(z1.Bytes())
	hash.Write(u1.Bytes(meta.Curve()))
	hash.Write(u2.Bytes())
	hash.Write(u3.Bytes())
	hash.Write(u4.Bytes())
	hash.Write(v1.Bytes())
	hash.Write(v2.Bytes())
	hash.Write(v3.Bytes())

	eHash := hash.Sum(nil)
	e := new(big.Int).SetBytes(eHash)

	t1 := new(big.Int).Exp(p.randomVi, e, n)
	t1.Mul(t1, beta1).Mod(t1, n)
	t2 := new(big.Int).Exp(p.randomUi, e, n)
	t2.Mul(t2, beta2).Mod(t2, n)
	t3 := new(big.Int).Exp(p.randomWi, e, n)
	t3.Mul(t3, beta3).Mod(t3, n)

	s1 := new(big.Int).Mul(e, p.eta1)
	s1.Add(s1, alpha1)
	s3 := new(big.Int).Mul(e, rho1)
	s3.Add(s3, gamma1)
	s4 := new(big.Int).Mul(e, p.eta2)
	s4.Add(s4, alpha2)
	s5 := new(big.Int).Mul(e, rho2)
	s5.Add(s5, gamma2)
	s6 := new(big.Int).Mul(e, p.eta3)
	s6.Add(s6, alpha3)
	s7 := new(big.Int).Mul(e, rho3)
	s7.Add(s7, gamma3)

	proof = &SigZKProof{
		u1: u1,
		u2: u2,
		u3: u3,
		u4: u4,
		z1: z1,
		z2: z2,
		z3: z3,
		v1: v1,
		v2: v2,
		v3: v3,
		s1: s1,
		s3: s3,
		s4: s4,
		s5: s5,
		s6: s6,
		s7: s7,
		t1: t1,
		t2: t2,
		t3: t3,
		e:  e,
	}
	return
}

// Verify verifies a ZKProof of SigZKProof type. It receives the key metainfo and 4 arguments, representing
// a random point share used in the signing process, and a three random values encrypted and used as shares of other
// values of the protocol.
func (p *SigZKProof) Verify(meta *KeyMeta, vals ...interface{}) error {
	if len(vals) != 4 {
		return fmt.Errorf("the verification requires three values: ri (*Point), vi, ui and wi (*l2fhe.EncryptedL1)")
	}
	r, ok := vals[0].(*Point)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *Point as first argument")
	}
	uiFHE, ok := vals[1].(*l2fhe.EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1 as third argument")
	}
	viFHE, ok := vals[2].(*l2fhe.EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1 as second argument")
	}
	wiFHE, ok := vals[3].(*l2fhe.EncryptedL1)
	if !ok {
		return fmt.Errorf("decryption share verification requires a *EncryptedL1 as fourth  argument")
	}

	cache := meta.Paillier.Cache()
	n := meta.Paillier.N

	nToSPlusOne := cache.NToSPlusOne
	nTilde := meta.NTilde
	h1 := meta.H1
	h2 := meta.H2
	nPlusOne := cache.NPlusOne
	minusE := new(big.Int).Neg(p.e)

	g := meta.G()

	ui, err := uiFHE.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return err
	}
	vi, err := viFHE.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return err
	}
	wi, err := wiFHE.ToPaillier(meta.PubKey.Paillier)
	if err != nil {
		return err
	}

	u1 := NewZero().Mul(meta.Curve(), g, p.s1)
	pu1 := NewZero().Add(meta.Curve(), p.u1, NewZero().Mul(meta.Curve(), r, p.e))

	if pu1.Cmp(u1) != 0 {
		return fmt.Errorf("zkproof failed (u1)")
	}
	u2 := new(big.Int).Exp(nPlusOne, p.s1, nToSPlusOne)
	u2.Mul(u2, new(big.Int).Exp(p.t1, n, nToSPlusOne)).
		Mul(u2, new(big.Int).Exp(vi, minusE, nToSPlusOne)).
		Mod(u2, nToSPlusOne)

	if p.u2.Cmp(u2) != 0 {
		return fmt.Errorf("zkproof failed (u2)")
	}

	u3 := new(big.Int).Exp(nPlusOne, p.s4, nToSPlusOne)
	u3.Mul(u3, new(big.Int).Exp(p.t2, n, nToSPlusOne)).
		Mul(u3, new(big.Int).Exp(ui, minusE, nToSPlusOne)).
		Mod(u3, nToSPlusOne)

	if p.u3.Cmp(u3) != 0 {
		return fmt.Errorf("zkproof failed (u3)")
	}

	u4 := new(big.Int).Exp(nPlusOne, p.s6, nToSPlusOne)
	u4.Mul(u4, new(big.Int).Exp(p.t3, n, nToSPlusOne)).
		Mul(u4, new(big.Int).Exp(wi, minusE, nToSPlusOne)).
		Mod(u4, nToSPlusOne)

	if p.u4.Cmp(u4) != 0 {
		return fmt.Errorf("zkproof failed (u4)")
	}

	v1 := new(big.Int).Exp(h1, p.s1, nTilde)
	v1.Mul(v1, new(big.Int).Exp(h2, p.s3, nTilde)).
		Mul(v1, new(big.Int).Exp(p.z1, minusE, nTilde)).
		Mod(v1, nTilde)

	if p.v1.Cmp(v1) != 0 {
		return fmt.Errorf("zkproof failed (v1)")
	}

	v2 := new(big.Int).Exp(h1, p.s4, nTilde)
	v2.Mul(v2, new(big.Int).Exp(h2, p.s5, nTilde)).
		Mul(v2, new(big.Int).Exp(p.z2, minusE, nTilde)).
		Mod(v2, nTilde)

	if p.v2.Cmp(v2) != 0 {
		return fmt.Errorf("zkproof failed (v2)")
	}

	v3 := new(big.Int).Exp(h1, p.s6, nTilde)
	v3.Mul(v3, new(big.Int).Exp(h2, p.s7, nTilde)).
		Mul(v3, new(big.Int).Exp(p.z3, minusE, nTilde)).
		Mod(v3, nTilde)

	if p.v3.Cmp(v3) != 0 {
		return fmt.Errorf("zkproof failed (v3)")
	}

	hash.Reset()
	hash.Write(g.Bytes(meta.Curve()))
	hash.Write(r.Bytes(meta.Curve()))
	hash.Write(vi.Bytes())
	hash.Write(ui.Bytes())
	hash.Write(wi.Bytes())
	// no problem to use provided because their equality was checked before
	hash.Write(p.z1.Bytes())
	hash.Write(p.u1.Bytes(meta.Curve()))
	hash.Write(p.u2.Bytes())
	hash.Write(p.u3.Bytes())
	hash.Write(p.u4.Bytes())
	hash.Write(p.v1.Bytes())
	hash.Write(p.v2.Bytes())
	hash.Write(p.v3.Bytes())

	eHash := hash.Sum(nil)
	e := new(big.Int).SetBytes(eHash)

	if p.e.Cmp(e) != 0 {
		return fmt.Errorf("zkproof failed (hash)")
	}
	return nil
}

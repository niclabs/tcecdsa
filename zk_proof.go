package tcecdsa

import (
	"crypto/rand"
	"math/big"
)

type ZKProof interface {
	Verify() error
}

type RandValues struct {
	alpha, delta  *big.Int
	rho1, rho2    *big.Int
	beta1, beta2  *big.Int
	gamma, nu     *big.Int
	rho3, epsilon *big.Int
}

// Pi as seen on paper
type FirstZKProof struct {
	y              *big.Int
	z1, z2         *big.Int
	u1, u2, u3     *big.Int
	v1, v2, v3, v4 *big.Int
	s1, s2, s3     *big.Int
	t1, t2, t3, t4 *big.Int
}

// Pi' as seen on paper
type LastZKProof struct {
	y                      *big.Int
	z1, z2, z3             *big.Int
	u1, u2, u3             *big.Int
	v1, v2, v3, v4, v5     *big.Int
	s1, s2, s3             *big.Int
	t1, t2, t3, t4, t5, t6 *big.Int
}

// PiHat as seen on paper
type MiddleZKProof struct {
	y                      *big.Int
	z1, z2                 *big.Int
	u1, u2, u3             *big.Int
	v1, v2, v3, v4, v5, v6 *big.Int
	s1, s2, s3             *big.Int
	t1, t2, t3, t4         *big.Int
}

func NewFirstZKProof(p Participant) (*FirstZKProof, error) {
	h1 := p.params.H1
	h2 := p.params.H2
	x1 := p.x
	randValues, err := newRandomValues(p)
	if err != nil {
		return nil, err
	}
	z1 := new(big.Int).Mul(
		new(big.Int).Exp(h1, x1, nTilde),
		new(big.Int).Exp(h2, rho1, nTilde),
	)
	z1.Mod(z1, nTilde)

	return nil, nil
}

func newRandomValues(p Participant) (*RandValues, error) {
	randSrc := p.params.RandomSrc
	q := p.params.Q()
	n := p.params.N()
	nTilde := p.params.NTilde
	qCube := new(big.Int).Exp(q, big.NewInt(3), nil)
	qNTilde := new(big.Int).Mul(q, nTilde)
	qCubeNTilde := new(big.Int).Mul(qCube, nTilde)
	nMinusOne := new(big.Int).Sub(n, one)
	alpha, err := rand.Int(randSrc, qCube)
	if err != nil {
		return nil, err
	}
	delta, err := rand.Int(randSrc, qCube)
	if err != nil {
		return nil, err
	}
	rho1, err := rand.Int(randSrc, qNTilde)
	if err != nil {
		return nil, err
	}
	rho2, err := rand.Int(randSrc, qNTilde)
	if err != nil {
		return nil, err
	}
	beta1, err := rand.Int(randSrc, nMinusOne)
	if err != nil {
		return nil, err
	}
	beta1.Add(beta1, one)
	beta2, err := rand.Int(randSrc, nMinusOne)
	if err != nil {
		return nil, err
	}
	beta2.Add(beta2, one)
	gamma, err := rand.Int(randSrc, qCubeNTilde)
	if err != nil {
		return nil, err
	}
	nu, err := rand.Int(randSrc, qCubeNTilde)
	if err != nil {
		return nil, err
	}
	rho3, err := rand.Int(randSrc, q)
	if err != nil {
		return nil, err
	}
	epsilon, err := rand.Int(randSrc, q)
	if err != nil {
		return nil, err
	}
	return &RandValues{
		alpha:   alpha,
		delta:   delta,
		rho1:    rho1,
		rho2:    rho2,
		beta1:   beta1,
		beta2:   beta2,
		gamma:   gamma,
		nu:      nu,
		rho3:    rho3,
		epsilon: epsilon,
	}, nil
}

func NewMiddleZKProof() (*MiddleZKProof, error) {
	return nil, nil

}

func NewLastZKProof() (*LastZKProof, error) {
	return nil, nil
}

func (p *FirstZKProof) Verify() bool {

}

func (p *MiddleZKProof) Verify() bool {

}

func (p *LastZKProof) Verify() bool {

}

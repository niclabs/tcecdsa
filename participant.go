package tcecdsa

import (
	"crypto/rand"
	"github.com/actuallyachraf/gomorph/gaillier"
	"math/big"
)

type Participant struct {
	Index  uint8
	Rho    *big.Int
	Z      *big.Int
	x      *big.Int
	Y      *Point
	Round  int
	params *KeyMeta
}

func (p *Participant) checkComplete() error {
	return nil
}

func newParticipant(i uint8, params *KeyMeta) (participant *Participant, err error) {
	xi, err := randFieldElement(params.Curve, params.RandomSrc)
	xix, xiy := params.Curve.ScalarBaseMult(xi.Bytes())
	if err != nil {
		return
	}
	return &Participant{
		Index:  i,
		x:      xi,
		Y:      &Point{xix, xiy},
		params: params,
	}, nil
}

func (p *Participant) AlphaI() ([]byte, error) {
	a, err := gaillier.Encrypt(p.params.PaillierPK, p.x.Bytes())
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (p *Participant) SignRound1(M string) (u, v []byte, zk ZKProof, err error) {
	if err := p.checkComplete(); err != nil {
		return
	}
	// Chooses randomly Rho \in Zq and computes Z = Rho^-1 mod q
	rho, err := randFieldElement(p.params.Curve, p.params.RandomSrc)
	if err != nil {
		return
	}
	p.Rho = rho
	u, err = gaillier.Encrypt(p.params.PaillierPK, rho.Bytes())
	if err != nil {
		return
	}
	v = gaillier.Mul(p.params.PaillierPK, p.params.Alpha, p.Rho.Bytes())
	// TODO zkproofs
	return
}

// Round 3 in protocol
func (p *Participant) SignRound2(u, v []byte) (ri *Point, wi []byte, zk ZKProof, err error) {
	ki, err := rand.Int(p.params.RandomSrc, p.params.Q())
	if err != nil {
		return
	}
	q6 := new(big.Int).Exp(p.params.Q(), big.NewInt(6), nil)
	ci, err := rand.Int(p.params.RandomSrc, new(big.Int).Mul(q6, big.NewInt(2)))
	if err != nil {
		return
	}
	ci.Sub(p.params.Q(), q6)
	rix, riy := p.params.Curve.ScalarBaseMult(ki.Bytes())
	ri = &Point{rix, riy}

	ciq := new(big.Int).Mul(ci, p.params.Q())
	encrypted_ciq, err := gaillier.Encrypt(p.params.PaillierPK, ciq.Bytes())
	if err != nil {
		return
	}
	kiu := gaillier.Mul(p.params.PaillierPK, u, ki.Bytes())
	wi = gaillier.Add(p.params.PaillierPK, kiu, encrypted_ciq)
	// TODO ZKProof
	return
}


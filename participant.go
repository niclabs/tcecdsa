package tcecdsa

import (
	"github.com/actuallyachraf/gomorph/gaillier"
	"math/big"
)

type Participant struct {
	i      uint8
	ki     *big.Int
	zi     *big.Int
	xi     *big.Int
	pki    *Point
	round  int
	params *PubMeta
}

type RoundParams struct {
	A, B, AHat, BHat map[uint8][]byte
	R map[uint8]*Point
	PI map[uint8][]byte
}


func (p *Participant) checkComplete() error {
	return nil
}

func newParticipant(i uint8, params *PubMeta) (participant *Participant, err error) {
	xi, err := randFieldElement(params.Curve, params.RandomSrc)
	xix, xiy := params.Curve.ScalarBaseMult(xi.Bytes())
	if err != nil {
		return
	}
	return &Participant{
		i:      i,
		xi:     xi,
		pki:    &Point{xix, xiy},
		params: params,
	}, nil
}

// Round 1, Rounds 2 to t-1 and part of Round t (k_t generation)
func (p *Participant) SignRound1(M string, params RoundParams) (RoundParams, error) {
	if err := p.checkComplete(); err != nil {
		return RoundParams{}, err
	}
	// Chooses ki \in Zq and computes Zi = Ki^-1 mod q
	ki, err := randFieldElement(p.params.Curve, p.params.RandomSrc)
	if err != nil {
		return RoundParams{}, err
	}
	p.ki = ki
	zi := new(big.Int).ModInverse(ki, p.params.Curve.Params().N)
	p.zi = zi
	xizi := new(big.Int).Mod(new(big.Int).Mul(p.xi, zi), p.params.Curve.Params().N)
	if p.i == 0 {
		a, err := gaillier.Encrypt(p.params.PaillierPK, zi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		b, err := gaillier.Encrypt(p.params.PaillierPK, xizi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		params.A[p.i] = a
		params.B[p.i] = b
		params.AHat[p.i] = nil
		params.BHat[p.i] = nil
	} else if p.i < p.params.T - 1 {
		a := gaillier.Mul(p.params.PaillierPK, params.A[p.i - 1], zi.Bytes())
		b := gaillier.Mul(p.params.PaillierPK, params.B[p.i - 1], xizi.Bytes())
		aHat, err := gaillier.Encrypt(p.params.PaillierPK, zi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		bHat, err := gaillier.Encrypt(p.params.PaillierPK, xizi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		params.A[p.i] = a
		params.B[p.i] = b
		params.AHat[p.i] = aHat
		params.BHat[p.i] = bHat
	}
	return params, nil
}

// Rounds t+1 to 2t-2 and part of Round 2t-1 (R_1 generation)
func (p *Participant) SignRound2(params RoundParams) (RoundParams, error) {
	if p.i == p.params.T - 1 {
		pix, piy := p.params.Curve.ScalarBaseMult(p.ki.Bytes())
		params.R[p.i] = &Point{pix, piy}
	} else {
		g := params.R[p.i + 1]
		pix, piy := p.params.Curve.ScalarMult(g.x, g.y, p.ki.Bytes())
		params.R[p.i] = &Point{pix, piy}
	}
	return params, nil
}

func (p *Participant) SignRound3(params RoundParams) {

}
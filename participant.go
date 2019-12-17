package tcecdsa

import (
	"github.com/actuallyachraf/gomorph/gaillier"
	"math/big"
)

type Participant struct {
	Index  uint8
	Ki     *big.Int
	Zi     *big.Int
	xi     *big.Int
	Yi     *Point
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
		Index:  i,
		xi:     xi,
		Yi:     &Point{xix, xiy},
		params: params,
	}, nil
}



func (p *Participant) AlphaI() ([]byte, error) {
	a, err := gaillier.Encrypt(p.params.PaillierPK, p.xi.Bytes())
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Round 1, Rounds 2 to t-1 and part of Round t (k_t generation)
func (p *Participant) SignRound1(M string, params RoundParams) (RoundParams, error) {
	if err := p.checkComplete(); err != nil {
		return RoundParams{}, err
	}
	// Chooses Ki \in Zq and computes Zi = Ki^-1 mod q
	ki, err := randFieldElement(p.params.Curve, p.params.RandomSrc)
	if err != nil {
		return RoundParams{}, err
	}
	p.Ki = ki
	zi := new(big.Int).ModInverse(ki, p.params.Curve.Params().N)
	p.Zi = zi
	xizi := new(big.Int).Mod(new(big.Int).Mul(p.xi, zi), p.params.Curve.Params().N)
	if p.Index == 0 {
		a, err := gaillier.Encrypt(p.params.PaillierPK, zi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		b, err := gaillier.Encrypt(p.params.PaillierPK, xizi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		params.A[p.Index] = a
		params.B[p.Index] = b
		params.AHat[p.Index] = nil
		params.BHat[p.Index] = nil
	} else if p.Index < p.params.T - 1 {
		a := gaillier.Mul(p.params.PaillierPK, params.A[p.Index- 1], zi.Bytes())
		b := gaillier.Mul(p.params.PaillierPK, params.B[p.Index- 1], xizi.Bytes())
		aHat, err := gaillier.Encrypt(p.params.PaillierPK, zi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		bHat, err := gaillier.Encrypt(p.params.PaillierPK, xizi.Bytes())
		if err != nil {
			return RoundParams{}, err
		}
		params.A[p.Index] = a
		params.B[p.Index] = b
		params.AHat[p.Index] = aHat
		params.BHat[p.Index] = bHat
	}
	return params, nil
}

// Rounds t+1 to 2t-2 and part of Round 2t-1 (R_1 generation)
func (p *Participant) SignRound2(params RoundParams) (RoundParams, error) {
	if p.Index == p.params.T - 1 {
		pix, piy := p.params.Curve.ScalarBaseMult(p.Ki.Bytes())
		params.R[p.Index] = &Point{pix, piy}
	} else {
		g := params.R[p.Index+ 1]
		pix, piy := p.params.Curve.ScalarMult(g.x, g.y, p.Ki.Bytes())
		params.R[p.Index] = &Point{pix, piy}
	}
	return params, nil
}

func (p *Participant) SignRound3(params RoundParams) {

}
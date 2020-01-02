package tcecdsa

import (
	"crypto/rand"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type Participant struct {
	Index         uint8
	Rho           *big.Int
	Exi           *l2fhe.EncryptedL1
	Yi            *Point
	params        *Params
	PaillierShare *tcpaillier.KeyShare
}

func (p *Participant) Init() error {
	xi, err := rand.Int(p.params.RandomSrc, p.params.Q())
	if err != nil {
		return err
	}
	yix, yiy := p.params.Curve.ScalarBaseMult(xi.Bytes())
	p.Yi = &Point{yix, yiy}
	exi, err := p.params.PaillierPK.Encrypt(xi)
	if err != nil {
		return err
	}
	p.Exi = exi
	return nil
}

func (p *Participant) ReceivePublicPointShares(yiList []*Point, xiList []*l2fhe.EncryptedL1, zkproofs []*ZKEncryptX) (err error) {
	for _, proof := range zkproofs {
		if err2 := proof.Verify(p); err != nil {
			err = err2
			return
		}
	}
	yP := new(Point).Set(p.Yi)
	for _, yi := range yiList {
		x, y := p.params.Curve.Add(yP.X, yP.Y, yi.X, yi.Y)
		yP.X = x
		yP.Y = y
	}
	exP := p.Exi.Clone()
	var err2 error
	for _, xi := range xiList {
		exP, err2 = p.params.PaillierPK.AddL1(exP, xi)
		if err2 != nil {
			err = err2
			return
		}
	}
	return
}

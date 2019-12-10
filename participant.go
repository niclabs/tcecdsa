package tcecdsa

import (
	"math/big"
)

type Participant struct {
	id int
	round int
	Params ProtocolParams
	xi, yi *big.Int
	M string
}

func (p *Participant) checkComplete() error {

}

func (p *Participant) SignRound1() error {
	if err := p.checkComplete(); err != nil {
		return err
	}
	p.
}

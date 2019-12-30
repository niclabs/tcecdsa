package tcecdsa

import (
	"github.com/niclabs/tcpaillier"
	"math/big"
)

type Participant struct {
	Index         uint8
	Rho           *big.Int
	x             *big.Int
	Y             *Point
	params        *Params
	PaillierShare *tcpaillier.KeyShare
}

func (p *Participant) Init() error {

}

func (p *Participant) Receive

package tcecdsa

import "math/big"

type Point struct{ X, Y *big.Int }


func (p *Point) Set(p2 *Point) *Point{
	p.X = new(big.Int).Set(p2.X)
	p.Y = new(big.Int).Set(p2.Y)
	return p
}

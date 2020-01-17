package tcecdsa

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// Point represents a point in a discrete elliptic curve.
type Point struct{ X, Y *big.Int }

// NewZero returns a new point centered in (0,0)
func NewZero() *Point {
	return NewPoint(new(big.Int), new(big.Int))
}

// NewPoint returns a new point centered in (x, y)
func NewPoint(x, y *big.Int) *Point {
	return &Point{x, y}
}

// Clone copies the x and y coordinates of a point.
func (p *Point) Clone() *Point {
	np := NewZero()
	np.X = new(big.Int).Set(p.X)
	np.Y = new(big.Int).Set(p.Y)
	return np
}

// Neg negates a point, inverting its y coordinate.
func (p *Point) Neg(p2 *Point) *Point {
	p.X = new(big.Int).Set(p2.X)
	p.Y.Neg(p2.Y)
	return p
}

// Mul multiplies a point by a scalar, using a given elliptic curve.
func (p *Point) Mul(curve elliptic.Curve, p1 *Point, k *big.Int) *Point {
	x, y := curve.ScalarMult(p1.X, p1.Y, k.Bytes())
	if k.Cmp(zero) < 0 {
		y.Neg(y) // k.Bytes() only encodes positive numbers
	}
	p.X, p.Y = x, y
	return p
}

// BaseMul multiplies the curve base point by a scalar, using a given elliptic curve.
func (p *Point) BaseMul(curve elliptic.Curve, k *big.Int) *Point {
	x, y := curve.ScalarBaseMult(k.Bytes())
	p.X, p.Y = x, y
	if k.Cmp(zero) < 0 {
		p.Neg(p) // k.Bytes() only encodes positive numbers
	}
	return p
}

// Bytes transforms the point in a unique byte representation, based in Gob.Encode.
func (p *Point) Bytes(curve elliptic.Curve) []byte {
	return elliptic.Marshal(curve, p.X, p.Y)
}

// SetBytes transforms a byte array into a point, using elliptic.UnmarshalSignature method.
func (p *Point) SetBytes(curve elliptic.Curve, b []byte) (p2 *Point, err error) {
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil {
		err = fmt.Errorf("unmarshaling failed")
		return
	}
	p.X, p.Y = x, y
	p2 = p
	return
}

// Add adds a point with another, using a given elliptic curve.
func (p *Point) Add(curve elliptic.Curve, pList ...*Point) *Point {
	x, y := new(big.Int), new(big.Int)
	for _, pi := range pList {
		x, y = curve.Add(x, y, pi.X, pi.Y)
	}
	p.X, p.Y = x, y
	return p
}

// Cmp returns -1 if the first point is smaller than the second one (comparing x, then y coordinates),
// 0 if they are equal and 1 if the second point is smaller than the first one.
func (p *Point) Cmp(p2 *Point) int {
	switch p.X.Cmp(p2.X) {
	case -1:
		return -1
	case 1:
		return 1
	default:
		return p.Y.Cmp(p2.Y)
	}
}

// String returns the string representation of the point.
func (p *Point) String() string {
	return fmt.Sprintf("(%s,%s)", p.X, p.Y)
}

package tcecdsa

import (
	"crypto/elliptic"
	"github.com/niclabs/tcpaillier"
	"math/big"
	"testing"
)

var p0 = NewZero()
var curve = elliptic.P256()
var r1, _ = RandomFieldElement(curve)
var r2, _ = RandomFieldElement(curve)
var p1 = NewZero().BaseMul(curve, r1)
var p2 = NewZero().BaseMul(curve, r2)
var pFixed = NewPoint(big.NewInt(6), big.NewInt(4))
var pFixed2 = NewPoint(big.NewInt(3), big.NewInt(5))

func TestNewZero(t *testing.T) {
	if p0.X.Cmp(big.NewInt(0)) != 0 {
		t.Error("point x coordinate has not been set to 0")
		return
	}
	if p0.Y.Cmp(big.NewInt(0)) != 0 {
		t.Error("point y coordinate has not been set to 0")
		return
	}
}

func TestPoint_Clone(t *testing.T) {
	p2 := p1.Clone()
	if p1 == p2 {
		t.Error("point was not cloned")
		return
	}
	if p1.X == p2.X {
		t.Error("point x coordinate was not cloned")
		return
	}
	if p1.Y == p2.Y {
		t.Error("point y coordinate was not cloned")
		return
	}
	if p1.X.Cmp(p2.X) != 0 {
		t.Error("point x coordinate has not the same values on both points")
		return
	}
	if p1.Y.Cmp(p2.Y) != 0 {
		t.Error("point y coordinate has not the same values on both points")
		return
	}
}

func TestPoint_Add(t *testing.T) {
	var pSumX, pSumY = curve.Add(p1.X, p1.Y, p2.X, p2.Y)
	var pSum = NewPoint(pSumX, pSumY)
	sum := NewZero().Add(curve, p1, p2)
	if sum.Cmp(pSum) != 0 {
		t.Errorf("sub should have been %s but it is %s", pSum, sum)
		return
	}
}

func TestPoint_BaseMul(t *testing.T) {
	baseX, baseY := curve.Params().Gx, curve.Params().Gy
	base := NewPoint(baseX, baseY)
	sumThree := NewZero().Add(curve, base, base, base)
	mulThree := NewZero().BaseMul(curve, big.NewInt(3))
	if sumThree.Cmp(mulThree) != 0 {
		t.Errorf("mulThree should have been equal to sumThree but it is not")
		return
	}
	sumMinusThree := NewZero().Neg(sumThree)
	mulMinusThree := NewZero().BaseMul(curve, big.NewInt(-3))
	if sumMinusThree.Cmp(mulMinusThree) != 0 {
		t.Errorf("mulMinusThree should have been equal to sumMinusThree but it is not")
		return
	}
}

func TestPoint_SetBytes(t *testing.T) {
	b := p1.Bytes(curve)
	c, err := NewZero().SetBytes(curve, b)
	if err != nil {
		t.Error("couldn't set point bytes to another point")
		return
	}
	if c.Cmp(p1) != 0 {
		t.Error("points are not equal")
		return
	}
}

func TestPoint_Cmp(t *testing.T) {
	if pFixed.Cmp(pFixed2) != 1 {
		t.Errorf("%s should have been greater than %s, but it is %d", pFixed, pFixed2, pFixed.Cmp(pFixed2))
	}
}

func TestPoint_Mul(t *testing.T) {
	sumThree := NewZero().Add(curve, p1, p1, p1)
	mulThree := NewZero().Mul(curve, p1, big.NewInt(3))
	if sumThree.Cmp(mulThree) != 0 {
		t.Errorf("mulThree should have been equal to sumThree but it is not")
		return
	}
	sumMinusThree := NewZero().Neg(sumThree)
	mulMinusThree := NewZero().Mul(curve, p1, big.NewInt(-3))
	if sumMinusThree.Cmp(mulMinusThree) != 0 {
		t.Errorf("mulMinusThree should have been equal to sumMinusThree but it is not")
		return
	}
}

func TestPoint_MulZK(t *testing.T) {

	q := curve.Params().N
	qToThree := new(big.Int).Exp(q, big.NewInt(3), nil)

	nu, err := RandomFieldElement(curve)
	if err != nil {
		t.Error(err)
		return
	}

	y := NewZero().BaseMul(curve, nu)

	alpha, err := RandomInRange(new(big.Int), qToThree)
	if err != nil {
		t.Error(err)
		return
	}

	e, err := tcpaillier.RandomInt(256) // the hash
	if err != nil {
		t.Error(err)
		return
	}

	minusE := new(big.Int).Neg(e)

	s1 := new(big.Int).Mul(e, nu)
	s1.Add(s1, alpha)

	u1a := NewZero().BaseMul(curve, alpha)

	u1b := NewZero().BaseMul(curve, s1)
	u1b.Add(curve, u1b, NewZero().Mul(curve, y, minusE))

	if u1a.Cmp(u1b) != 0 {
		t.Error("zkproof failed")
		return
	}
}

func TestPoint_Neg(t *testing.T) {
	sum := NewZero().Add(curve, p1, p2)
	minusP1 := NewZero().Neg(p1)
	if !curve.IsOnCurve(minusP1.X, minusP1.Y) {
		t.Error("negative of point is not in curve")
		return
	}
	sub := NewZero().Add(curve, sum, minusP1)
	if sub.Cmp(p2) != 0 {
		t.Errorf("sub should have been %s but it is %s", p2, sub)
		return
	}
}

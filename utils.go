package tcecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

var zero = new(big.Int)
var one = new(big.Int).SetInt64(1)

// RandomFieldElement returns A random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
// Taken from Golang ECDSA implementation
func RandomFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// RandomInRange returns a number between an interval [min, max).
func RandomInRange(min, max *big.Int, randSource io.Reader) (r *big.Int, err error) {
	if min.Cmp(max) >= 0 {
		err = fmt.Errorf("min is equal or more than max")
		return
	}
	sub := new(big.Int).Sub(max, min)
	r, err = rand.Int(randSource, sub)
	if err != nil {
		return
	}
	r.Add(r, min)
	return
}

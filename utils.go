package tcecdsa

import (
	"crypto/elliptic"
	"io"
	"math/big"
)

var one = new(big.Int).SetInt64(1)

// randFieldElement returns A random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
// Taken from Golang ECDSA implementation
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
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

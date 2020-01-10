package tcecdsa

import (
	"crypto/elliptic"
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"hash"
	"io"
)

type NewKeyParams struct {
	PaillierFixed *tcpaillier.FixedParams
}

// NewKey returns a new distributed key share list, using the specified l (total number of nodes), k (threshold),
// curve (elliptic curve), hash (cryptographic hash), random source (randomSource) and params (additional params)
// If the params are nil, it creates them.
func NewKey(l, k uint8, curve elliptic.Curve, hash hash.Hash, randomSource io.Reader, params *NewKeyParams) (keyShares []*KeyShare, keyMeta *KeyMeta, err error) {
	if l < 2 {
		err = fmt.Errorf("keyShares number should be more than 1")
		return
	}
	var pk *l2fhe.PubKey
	var shares []*tcpaillier.KeyShare
	if params != nil && params.PaillierFixed != nil {
		pk, shares, err = l2fhe.NewFixedKey(curve.Params().BitSize, l, k, randomSource, params.PaillierFixed)
	} else {
		pk, shares, err = l2fhe.NewKey(curve.Params().BitSize, l, k, randomSource)
	}
	if err != nil {
		return
	}
	zkProofMeta, err := genZKProofMeta(randomSource)
	if err != nil {
		return
	}
	keyMeta = &KeyMeta{
		PubKey:      pk,
		ZKProofMeta: zkProofMeta,
		Curve:       curve,
		Hash:        hash,
	}
	keyShares = make([]*KeyShare, len(shares))
	for i, share := range shares {
		keyShares[i] = &KeyShare{
			Index:         uint8(i),
			PaillierShare: share,
		}
	}
	return
}

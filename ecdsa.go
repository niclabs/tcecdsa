package tcecdsa

import (
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
)

// NewKeyParams represents a group of params that the metod NewKey can use.
type NewKeyParams struct {
	PaillierFixed *tcpaillier.FixedParams // Paillier Fixed Params.
}

// NewKey returns a new distributed key share list, using the specified l (total number of nodes), k (threshold),
// curveName (elliptic curve name, between those Go supports by default) and params (additional params)
// If the params are nil, it creates them.
func NewKey(l, k uint8, curveName string, params *NewKeyParams) (keyShares []*KeyShare, keyMeta *KeyMeta, err error) {
	if l < 2 {
		err = fmt.Errorf("keyShares number should be more than 1")
		return
	}
	var pk *l2fhe.PubKey
	var shares []*tcpaillier.KeyShare
	zkProofMeta, err := genZKProofMeta()
	if err != nil {
		return
	}
	keyMeta = &KeyMeta{
		ZKProofMeta: zkProofMeta,
		CurveName:       curveName,
	}
	if params != nil && params.PaillierFixed != nil {
		pk, shares, err = l2fhe.NewFixedKey(keyMeta.Curve().Params().BitSize, l, k, params.PaillierFixed)
	} else {
		pk, shares, err = l2fhe.NewKey(keyMeta.Curve().Params().BitSize, l, k)
	}
	if err != nil {
		return
	}
	keyMeta.PubKey = pk
	keyShares = make([]*KeyShare, len(shares))
	for i, share := range shares {
		keyShares[i] = &KeyShare{
			Index:         uint8(i),
			PaillierShare: share,
		}
	}
	return
}

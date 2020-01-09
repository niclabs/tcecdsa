package tcecdsa

import (
	"crypto/elliptic"
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"hash"
	"io"
)

// NewKey returns a new distributed key share list, using the specified l (total number of nodes), k (threshold),
// curve (elliptic curve used), hash (hash function used) and randomSource (source of randomness).
func NewKey(l, k uint8, curve elliptic.Curve, hash hash.Hash, randomSource io.Reader) (keyShares []*KeyShare, keyMeta *KeyMeta, err error) {
	if l < 2 {
		err = fmt.Errorf("keyShares number should be more than 1")
		return
	}
	pk, shares, err := l2fhe.NewKey(curve.Params().BitSize, l, k, randomSource)
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

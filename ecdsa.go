package tcecdsa

import (
	"crypto/elliptic"
	"fmt"
	"github.com/niclabs/tcecdsa/l2fhe"
	"hash"
	"io"
	"math/big"
)

type EcdsaSignature struct {
	R, S *big.Int
}

func NewKey(l, k uint8, curve elliptic.Curve, hash hash.Hash, reader io.Reader) (keyShares []*KeyShare, keyMeta *KeyMeta, err error) {
	if l < 2 {
		err = fmt.Errorf("keyShares number should be more than 1")
		return
	}
	pk, shares, err := l2fhe.NewKey(curve.Params().BitSize, l, k, reader)
	if err != nil {
		return
	}
	zkProofMeta, err := genZKProofMeta(reader)
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

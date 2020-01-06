package tcecdsa_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/niclabs/tcecdsa"
	"testing"
)

const L = 5
const K = 3

var Curve = elliptic.P224()
var Random = rand.Reader

func TestNewKey(t *testing.T) {
	keyShares, keyMeta, err := tcecdsa.NewKey(L, K, Curve, Random)
	if err != nil {
		t.Error(err)
		return
	}

	zkps := make([]*tcecdsa.KeyGenZKProof, len(keyShares))

	for i, share := range keyShares {
		zkps[i], err = share.Init(keyMeta)
		if err != nil {
			t.Error(err)
			return
		}
	}
	for i, zkp := range zkps {
		if err := zkp.Verify(keyMeta, keyShares[i].Yi, keyShares[i].Exi); err != nil {
			t.Error(err)
			return
		}
	}
}

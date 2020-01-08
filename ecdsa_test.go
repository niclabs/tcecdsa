package tcecdsa_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"github.com/niclabs/tcecdsa"
	"math/big"
	"testing"
)

const L = 5
const K = 3
var exampleText = []byte("hello world")

var Curve = elliptic.P224()
var Hash = sha256.New()
var Random = rand.Reader

func TestNewKey(t *testing.T) {
	shares, keyMeta, err := tcecdsa.NewKey(L, K, Curve, Hash, Random)
	if err != nil {
		t.Error(err)
		return
	}

	var h []byte

	states := make([]*tcecdsa.SigState, len(shares))

	keyInitMessages := make([]*tcecdsa.KeyInitMessage, len(shares))
	round1Messages := make([]*tcecdsa.SigInitMessage, 0)
	round2Messages := make([]*tcecdsa.Round2Message, 0)
	round3Messages := make([]*tcecdsa.Round3Message, 0)
	rs := make([]*big.Int, 0)
	ss := make([]*big.Int, 0)

	// Key Generation
	for i, share := range shares {
		keyInitMessages[i], err = share.Init(keyMeta)
		if err != nil {
			t.Error(err)
			return
		}
	}
	for _, msg := range keyInitMessages {
		if err := msg.Proof.Verify(keyMeta, msg.Yi, msg.AlphaI); err != nil {
			t.Error(err)
			return
		}
	}
	for _, share := range shares {
		if err := share.SetKey(keyMeta, keyInitMessages...); err != nil {
			t.Error(err)
			return
		}
	}

	// Getting public key

	pk, err := keyMeta.GetKeys(keyInitMessages...)
	if err != nil {
		t.Error(err)
		return
	}


	// State Creation
	for i, share := range shares {
		states[i], h, err = share.NewSigState(keyMeta, exampleText)
		if err != nil {
			t.Error(err)
			return
		}
	}

	// Round 1
	for _, state := range states {
		msg, err := state.Round1()
		if err != nil {
			t.Error(err)
			return
		}
		round1Messages = append(round1Messages, msg)
	}
	// Round 2
	for _, share := range states {
		msg, err := share.Round2(round1Messages...)
		if err != nil {
			t.Error(err)
			return
		}
		round2Messages = append(round2Messages, msg)
	}

	// Round 3
	for _, share := range states {
		msg, err := share.Round3(round2Messages...)
		if err != nil {
			t.Error(err)
			return
		}
		round3Messages = append(round3Messages, msg)
	}

	// Round 4
	for _, share := range states {
		r, s, err := share.Round4(round3Messages...)
		if err != nil {
			t.Error(err)
			return
		}
		rs = append(rs, r)
		ss = append(ss, s)
	}

	for i := 0; i < len(rs); i++ {
		if ok := ecdsa.Verify(pk, h, rs[i], ss[i]); !ok {
			t.Errorf("verification failed: %d", i)
			return
		}
	}
}

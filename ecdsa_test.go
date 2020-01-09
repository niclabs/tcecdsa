package tcecdsa_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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

	// Setup
	shares, keyMeta, err := tcecdsa.NewKey(L, K, Curve, Hash, Random)
	if err != nil {
		t.Error(err)
		return
	}
	var h []byte
	states := make([]*tcecdsa.SigSession, 0)
	keyInitMessages := make(tcecdsa.KeyInitMessageList, 0)
	round1Messages := make(tcecdsa.Round1MessageList, 0)
	round2Messages := make(tcecdsa.Round2MessageList, 0)
	round3Messages := make(tcecdsa.Round3MessageList, 0)
	rs := make([]*big.Int, 0)
	ss := make([]*big.Int, 0)

	var pk *ecdsa.PublicKey

//	t.Run("KeyGen", func(t *testing.T) {
		for _, share := range shares {
			keyInitMessage, err := share.Init(keyMeta)
			if err != nil {
				t.Error(err)
				return
			}
			keyInitMessages = append(keyInitMessages, keyInitMessage)
		}
		for _, msg := range keyInitMessages {
			if err := msg.Proof.Verify(keyMeta, msg.Yi, msg.AlphaI); err != nil {
				t.Error(err)
				return
			}
		}
		for _, share := range shares {
			if err := share.SetKey(keyMeta, keyInitMessages); err != nil {
				t.Error(err)
				return
			}
		}
//	})

//	t.Run("GenPubKey", func(t *testing.T) {
		pk, err = keyMeta.GetPublicKey(keyInitMessages)
		if err != nil {
			t.Error(err)
			return
		}
//	})

//	t.Run("NewSigSession", func(t *testing.T) {
		for _, share := range shares {
			var state *tcecdsa.SigSession
			state, h, err = share.NewSigSession(keyMeta, exampleText)
			if err != nil {
				t.Error(err)
				return
			}
			states = append(states, state)
		}
//	})

//	t.Run("Round1", func(t *testing.T) {
		for _, state := range states {
			msg, err := state.Round1()
			if err != nil {
				t.Error(err)
				return
			}
			round1Messages = append(round1Messages, msg)
		}
//	})

//	t.Run("Round2", func(t *testing.T) {
		for _, share := range states {
			msg, err := share.Round2(round1Messages)
			if err != nil {
				t.Error(err)
				return
			}
			round2Messages = append(round2Messages, msg)
		}
//	})

//	t.Run("Round3", func(t *testing.T) {
		for _, share := range states {
			msg, err := share.Round3(round2Messages)
			if err != nil {
				t.Error(err)
				return
			}
			round3Messages = append(round3Messages, msg)
		}
//	})

	// Round 4
//	t.Run("GetSignature", func(t *testing.T) {
		for _, share := range states {
			r, s, err := share.GetSignature(round3Messages)
			if err != nil {
				t.Error(err)
				return
			}
			rs = append(rs, r)
			ss = append(ss, s)
		}
//	})

//	t.Run("Verify", func(t *testing.T) {
		for i := 0; i < len(rs); i++ {
			if ok := ecdsa.Verify(pk, h, rs[i], ss[i]); !ok {
				t.Errorf("verification failed: %d", i)
			} else {
				fmt.Printf("Signature %d is correct\n", i)
			}
		}
//	})
}

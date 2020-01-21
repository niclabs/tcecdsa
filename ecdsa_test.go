package tcecdsa_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"github.com/niclabs/tcecdsa"
	"github.com/niclabs/tcpaillier"
	"math/big"
	"testing"
)

const L = 5
const K = 3

var exampleText = []byte("hello world")

var Curve = "P-224"
var Hash = sha256.New()
var Random = rand.Reader

// Keys for curve_bitsize <= 224 (1792 bits, because paillier is 8*curve_bitsize)
// This allows us to test easily, because we don't need to wait for another paillier pair
var p, _ = new(big.Int).SetString("481843155987347819240471233018818582440288384824667225054816554801181862153791832386130859645260354756309645278837491351820327738110587630919202231210878510487358927457873959614389626766288687576223670770229149716938428974940517592276865576702001967378548748115710361363", 10)
var p1, _ = new(big.Int).SetString("240921577993673909620235616509409291220144192412333612527408277400590931076895916193065429822630177378154822639418745675910163869055293815459601115605439255243679463728936979807194813383144343788111835385114574858469214487470258796138432788351000983689274374057855180681", 10)
var q, _ = new(big.Int).SetString("412869555449418513088610723546515649758113679263497461143281964942533362549552387321171889833327035679850480855648596001543734177165640501544385552969893524814969820967880299485349586412916667152003711405804484319055891168516277276341589468276521027239786422345706510127", 10)
var q1, _ = new(big.Int).SetString("206434777724709256544305361773257824879056839631748730571640982471266681274776193660585944916663517839925240427824298000771867088582820250772192776484946762407484910483940149742674793206458333576001855702902242159527945584258138638170794734138260513619893211172853255063", 10)

func TestNewKey(t *testing.T) {
	params := &tcecdsa.NewKeyParams{
		PaillierFixed: &tcpaillier.FixedParams{
			P:  p,
			P1: p1,
			Q:  q,
			Q1: q1,
		},
	}

	shares, keyMeta, err := tcecdsa.NewKey(L, K, Curve, params)
	if err != nil {
		t.Error(err)
		return
	}
	states := make([]*tcecdsa.SigSession, 0)
	keyInitMessages := make(tcecdsa.KeyInitMessageList, 0)
	round1Messages := make(tcecdsa.Round1MessageList, 0)
	round2Messages := make(tcecdsa.Round2MessageList, 0)
	round3Messages := make(tcecdsa.Round3MessageList, 0)
	rs := make([]*big.Int, 0)
	ss := make([]*big.Int, 0)
	var pk *ecdsa.PublicKey

	Hash.Reset()
	Hash.Write(exampleText)
	h := Hash.Sum(nil)

	t.Run("KeyGen", func(t *testing.T) {
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
	})

	t.Run("GenPubKey", func(t *testing.T) {
		pk, err = keyMeta.GetPublicKey(keyInitMessages)
		if err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("NewSigSession", func(t *testing.T) {
		for _, share := range shares {
			var state *tcecdsa.SigSession
			state, err = share.NewSigSession(keyMeta, h)
			if err != nil {
				t.Error(err)
				return
			}
			states = append(states, state)
		}
	})

	t.Run("Round1", func(t *testing.T) {
		for _, state := range states {
			msg, err := state.Round1()
			if err != nil {
				t.Error(err)
				return
			}
			round1Messages = append(round1Messages, msg)
		}
	})

	t.Run("Round2", func(t *testing.T) {
		for _, share := range states {
			msg, err := share.Round2(round1Messages)
			if err != nil {
				t.Error(err)
				return
			}
			round2Messages = append(round2Messages, msg)
		}
	})

	t.Run("Round3", func(t *testing.T) {
		for _, share := range states {
			msg, err := share.Round3(round2Messages)
			if err != nil {
				t.Error(err)
				return
			}
			round3Messages = append(round3Messages, msg)
		}
	})

	// Round 4
	t.Run("GetSignature", func(t *testing.T) {
		for _, share := range states {
			r, s, err := share.GetSignature(round3Messages)
			if err != nil {
				t.Error(err)
				return
			}
			rs = append(rs, r)
			ss = append(ss, s)
		}
	})

	t.Run("Verify", func(t *testing.T) {
		for i := 0; i < len(rs); i++ {
			if ok := ecdsa.Verify(pk, h, rs[i], ss[i]); !ok {
				t.Errorf("verification failed")
				return
			}
		}
	})
}

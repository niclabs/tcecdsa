package tcecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/actuallyachraf/gomorph/gaillier"
	"io"
	"math/big"
)

type Config struct {
	ParticipantsNumber uint8
	Reader             io.Reader
}

type Point struct{ X, Y *big.Int }

func CreateParticipants(curve elliptic.Curve, config *Config) (participants []*Participant, pubMeta *KeyMeta, paillierSK *gaillier.PrivKey, err error) {
	if config.ParticipantsNumber < 2 {
		err = fmt.Errorf("participants should be more than 1, but it is %d", config.ParticipantsNumber)
		return
	}
	reader := rand.Reader
	if config.Reader == nil {
		reader = config.Reader
	}
	NTildeGen, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	NTilde := new(big.Int).Mul(NTildeGen.Primes[0], NTildeGen.Primes[1])
	H1, err := rand.Int(rand.Reader, NTilde)
	if err != nil {
		return
	}
	H2, err := rand.Int(rand.Reader, NTilde)
	if err != nil {
		return
	}
	pubMeta = &KeyMeta{
		T:         config.ParticipantsNumber,
		Curve:     curve,
		RandomSrc: reader,
	}
	zkProofMeta := &ZKProofMeta{
		NTilde: NTilde,
		H1:     H1,
		H2:     H2,
	}
	keySize := 8 * pubMeta.Q().BitLen()
	paillierPK, paillierSK, err := gaillier.GenerateKeyPair(reader, keySize)
	if err != nil {
		return
	}
	pubMeta.PaillierPK = paillierPK
	participants = make([]*Participant, config.ParticipantsNumber)
	for i := uint8(0); i < config.ParticipantsNumber; i++ {
		participant, err := newParticipant(i, pubMeta)
		if err != nil {
			return
		}
		participants[i] = participant
		pubMeta.PubKeys[i] = participant.Y
	}
	// Create alpha and Y
	var alpha []byte
	y := new(Point)
	for i, p := range participants {
		if i == 0 {
			alpha, err = p.AlphaI()
			if err != nil {
				return
			}
			y = p.Y
		} else {
			alpha2, err := p.AlphaI()
			if err != nil {
				return
			}
			alpha = gaillier.Add(paillierPK, alpha, alpha2)
			yx, yy := curve.Add(p.Y.X, p.Y.Y, y.X, y.Y)
			y.X, y.Y = yx, yy
		}
	}
	pubMeta.Alpha = alpha
	pubMeta.Y = y
	return
}

// Round 2, now centralized
func (params *KeyMeta) GetUV(uList, vList [][]byte, zkList []ZKProof) (u, v []byte, err error) {
	for _, zkp := range zkList {
		if err = zkp.Verify(); err != nil {
			return
		}
	}
	for i, ui := range uList {
		if i == 0 {
			u = ui
		} else {
			u = gaillier.Add(params.PaillierPK, u, ui)
		}
	}
	for i, vi := range vList {
		if i == 0 {
			v = vi
		} else {
			v = gaillier.Add(params.PaillierPK, v, vi)
		}
	}
	return
}

// Round 4, 5 and 6 now centralized
func (params *KeyMeta) JoinSigShares(rList []*Point, wList [][]byte, zkList []ZKProof, u, v []byte, paillierSK *gaillier.PrivKey) (sign []byte, err error) {
	// Round 4, but centralized
	for _, zkp := range zkList {
		if err = zkp.Verify(); err != nil {
			return
		}
	}
	R := new(Point)
	for i, ri := range rList {
		if i == 0 {
			R.X, R.Y = ri.X, ri.Y
		} else {
			rx, ry := params.Curve.Add(R.X, R.Y, ri.X, ri.Y)
			R.X, R.Y = rx, ry
		}
	}
	r := new(big.Int).Mod(R.X, params.Q())
	var w []byte
	for i, wi := range wList {
		if i == 0 {
			w = wi
		} else {
			w = gaillier.Add(params.PaillierPK, w, wi)
		}
	}
	// Round 5, but centralized
	nuByte, err := gaillier.Decrypt(paillierSK, w)
	if err != nil {
		return
	}
	nu := new(big.Int).SetBytes(nuByte)
	psi := new(big.Int).ModInverse(nu, params.Q())
	rv := gaillier.Mul(params.PaillierPK, v, r.Bytes())
	mu := gaillier.Mul(params.PaillierPK, u, m.Bytes())
	// Round 6, but centralized
	return
}

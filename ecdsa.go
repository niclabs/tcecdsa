package tcecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/actuallyachraf/gomorph/gaillier"
	"github.com/niclabs/tcecdsa/l2fhe"
	"io"
	"math/big"
)

type Config struct {
	ParticipantsNumber uint8
	Threshold          uint8
	Reader             io.Reader
}

func NewParams(curve elliptic.Curve, config *Config) (participants []*Participant, params *Params, err error) {
	if config.ParticipantsNumber < 2 {
		err = fmt.Errorf("participants should be more than 1")
		return
	}
	reader := rand.Reader
	if config.Reader == nil {
		reader = config.Reader
	}
	// New Pallier threshold Key
	nLength := 8 * curve.Params().BitSize
	pk, shares, err := l2fhe.NewKey(nLength, config.ParticipantsNumber, config.Threshold, reader)
	if err != nil {
		return
	}
	zkProofMeta, err := GenZKProofMeta(reader)
	if err != nil {
		return
	}
	params = &Params{
		L:           config.ParticipantsNumber,
		K:           0,
		PaillierPK:  pk,
		Curve:       curve,
		RandomSrc:   reader,
		ZKProofMeta: zkProofMeta,
	}
	participants = make([]*Participant, len(shares))
	for i, share := range shares {
		participants[i] = &Participant{
			Index:         uint8(i),
			PaillierShare: share,
			params:        params,
		}
	}
	return
}

// Round 2, now centralized
func (params *Params) GetUV(uList, vList [][]byte, zkList []ZKProof) (u, v []byte, err error) {
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
func (params *Params) JoinSigShares(rList []*Point, wList [][]byte, zkList []ZKProof, u, v []byte, paillierSK *gaillier.PrivKey) (sign []byte, err error) {
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

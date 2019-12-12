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

type Point struct{ x, y *big.Int }

func CreateParticipants(curve elliptic.Curve, config *Config) (participants []*Participant, pubMeta *PubMeta, privMeta *PrivMeta, err error) {
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
	pubMeta = &PubMeta{
		T:         config.ParticipantsNumber,
		Curve:     curve,
		RandomSrc: reader,
		PubKeys:   make([]*Point, config.ParticipantsNumber),
		NTilde:    NTilde,
		H1:        H1,
		H2:        H2,
	}
	keySize := pubMeta.N().BitLen()
	paillierPK, paillierSK, err := gaillier.GenerateKeyPair(reader, keySize)
	if err != nil {
		return
	}
	pubMeta.PaillierPK = paillierPK
	privMeta = &PrivMeta{
		PaillierSK: paillierSK,
	}
	participants = make([]*Participant, config.ParticipantsNumber)
	for i := uint8(0); i < config.ParticipantsNumber; i++ {
		participant, err := newParticipant(i, pubMeta)
		if err != nil {
			return
		}
		participants[i] = participant
		pubMeta.PubKeys[i] = participant.pki
	}
	return
}

package l2fhe_test

import (
	"crypto/rand"
	"github.com/niclabs/tcecdsa/l2fhe"
	"math/big"
	"testing"
)

const bitSize = 128
const l = 5
const k = 3

var four = big.NewInt(4)
var fifty = big.NewInt(50)
var seventy = big.NewInt(70)
var oneHundredTwenty = big.NewInt(120)
var threeThousandFiveHundred = big.NewInt(3500)
var fourteenThousand = big.NewInt(14000)

func TestL2TCPaillier_Encrypt(t *testing.T) {
	l2, keyShares, err := l2fhe.NewL2TCPaillier(bitSize, l, k, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	pk := l2.PubKey

	encFifty, err := l2.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}
	if encFifty.Verify(pk) != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL1(share, encFifty)
		if err != nil {
			t.Error(err)
			return
		}
		if ds.Verify(pk) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := l2.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}

	if decrypted.Cmp(fifty) != 0 {
		t.Errorf("values are distinct: decrypted: %s and first value was %d", decrypted, fifty)
		return
	}
}

func TestL2TCPaillier_AddL1(t *testing.T) {
	l2, keyShares, err := l2fhe.NewL2TCPaillier(bitSize, l, k, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	pk := l2.PubKey

	encFifty, err := l2.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	if encFifty.Verify(pk) != nil {
		t.Error(err)
		return
	}

	eencSeventy, err := l2.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := eencSeventy.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encTwelve, err := l2.AddL1(encFifty, eencSeventy)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL1(share, encTwelve)
		if err != nil {
			t.Error(err)
			return
		}
		if ds.Verify(pk) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := l2.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(oneHundredTwenty) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, oneHundredTwenty)
		return
	}
}

func TestL2TCPaillier_MulConstL1(t *testing.T) {
	l2, keyShares, err := l2fhe.NewL2TCPaillier(bitSize, l, k, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	pk := l2.PubKey

	encFifty, err := l2.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encFifty.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := l2.MulConstL1(encFifty, seventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encThreeThousandFiveHundred.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL1(share, encThreeThousandFiveHundred)
		if err != nil {
			t.Error(err)
			return
		}
		if ds.Verify(pk) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := l2.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(threeThousandFiveHundred) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, threeThousandFiveHundred)
		return
	}
}

func TestL2TCPaillier_Mul(t *testing.T) {
	l2, keyShares, err := l2fhe.NewL2TCPaillier(bitSize, l, k, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	pk := l2.PubKey

	encFifty, err := l2.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encFifty.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	eencSeventy, err := l2.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := eencSeventy.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := l2.Mul(encFifty, eencSeventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encThreeThousandFiveHundred.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL2, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL2(share, encThreeThousandFiveHundred)
		if err != nil {
			t.Error(err)
			return
		}
		if ds.Verify(pk) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := l2.CombineSharesL2(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(threeThousandFiveHundred) != 0 {
		t.Errorf("Error Decrypting:\nDecrypted = %s\n Expected = %s\n   Module = %s", decrypted, threeThousandFiveHundred, pk.N)
		return
	}
}

func TestL2TCPaillier_AddL2(t *testing.T) {
	l2, keyShares, err := l2fhe.NewL2TCPaillier(bitSize, l, k, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	pk := l2.PubKey

	encFifty, err := l2.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encFifty.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encSenventy, err := l2.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encSenventy.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := l2.Mul(encFifty, encSenventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encThreeThousandFiveHundred.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encFourteenThousand, err := l2.AddL2(
		encThreeThousandFiveHundred,
		encThreeThousandFiveHundred,
		encThreeThousandFiveHundred,
		encThreeThousandFiveHundred,
	)

	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL2, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL2(share, encFourteenThousand)
		if err != nil {
			t.Error(err)
			return
		}
		if ds.Verify(pk) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := l2.CombineSharesL2(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(fourteenThousand) != 0 {
		t.Errorf("Error Decrypting:\nDecrypted = %s\n Expected = %s\n   Module = %s", decrypted, threeThousandFiveHundred, pk.N)
		return
	}
}

func TestL2TCPaillier_MulConstL2(t *testing.T) {
	l2, keyShares, err := l2fhe.NewL2TCPaillier(bitSize, l, k, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	pk := l2.PubKey

	encFifty, err := l2.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encFifty.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encSenventy, err := l2.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encSenventy.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := l2.Mul(encFifty, encSenventy)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encThreeThousandFiveHundred.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encFourteenThousand, err := l2.MulConstL2(encThreeThousandFiveHundred, four)
	if err != nil {
		t.Error(err)
		return
	}

		if err := encFourteenThousand.Verify(pk); err != nil {
			t.Error(err)
			return
		}

	decShares := make([]*l2fhe.DecryptedShareL2, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL2(share, encFourteenThousand)
		if err != nil {
			t.Error(err)
			return
		}
		if ds.Verify(pk) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := l2.CombineSharesL2(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(fourteenThousand) != 0 {
		t.Errorf("Error Decrypting:\nDecrypted = %s\n Expected = %s\n   Module = %s", decrypted, threeThousandFiveHundred, pk.N)
		return
	}
}

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

var five = big.NewInt(5)
var seven = big.NewInt(7)
var twelve = big.NewInt(12)
var thirtyFive = big.NewInt(35)

func TestL2TCPaillier_Encrypt(t *testing.T) {
	l2, keyShares, err := l2fhe.NewL2TCPaillier(bitSize, l, k, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	pk := l2.PubKey

	encFive, err := l2.Encrypt(five.Bytes())
	if err != nil {
		t.Error(err)
		return
	}
	if encFive.Verify(pk) != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL1(share, encFive)
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

	val, err := l2.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}

	decrypted := new(big.Int).SetBytes(val)
	if decrypted.Cmp(five) != 0 {
		t.Errorf("values are distinct: decrypted: %s and first value was %d", decrypted, five)
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

	encFive, err := l2.Encrypt(five.Bytes())
	if err != nil {
		t.Error(err)
		return
	}

	if encFive.Verify(pk) != nil {
		t.Error(err)
		return
	}

	encSeven, err := l2.Encrypt(seven.Bytes())
	if err != nil {
		t.Error(err)
		return
	}

	if err := encSeven.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encTwelve, err := l2.AddL1(encFive, encSeven)
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

	val, err := l2.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	decrypted := new(big.Int).SetBytes(val)
	if decrypted.Cmp(twelve) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, twelve)
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

	encFive, err := l2.Encrypt(five.Bytes())
	if err != nil {
		t.Error(err)
		return
	}

	if err := encFive.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encThirtyFive, err := l2.MulConstL1(encFive, seven)
	if err != nil {
		t.Error(err)
		return
	}

	if err := encThirtyFive.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL1(share, encThirtyFive)
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

	val, err := l2.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	decrypted := new(big.Int).SetBytes(val)
	if decrypted.Cmp(thirtyFive) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, thirtyFive)
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

	encFive, err := l2.Encrypt(five.Bytes())
	if err != nil {
		t.Error(err)
		return
	}

	if encFive.Verify(pk) != nil {
		t.Error(err)
		return
	}

	encSeven, err := l2.Encrypt(seven.Bytes())
	if err != nil {
		t.Error(err)
		return
	}

	if err :=  encSeven.Verify(pk); err != nil {
		t.Error(err)
		return
	}

	encThirtyFive, err := l2.Mul(encFive, encSeven)
	if err != nil {
		t.Error(err)
		return
	}


	decShares := make([]*l2fhe.DecryptedShareL2, 0)
	for _, share := range keyShares {
		ds, err := l2.PartialDecryptL2(share, encThirtyFive)
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

	val, err := l2.CombineSharesL2(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	decrypted := new(big.Int).SetBytes(val)
	if decrypted.Cmp(thirtyFive) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, twelve)
		return
	}
}

package l2fhe_test

import (
	"fmt"
	"github.com/niclabs/tcecdsa"
	"github.com/niclabs/tcecdsa/l2fhe"
	"github.com/niclabs/tcpaillier"
	"math/big"
	"testing"
)

const bitSize = 64
const l = 5
const k = 3

var four = big.NewInt(4)
var fifty = big.NewInt(50)
var seventy = big.NewInt(70)
var oneHundredTwenty = big.NewInt(120)
var threeThousandFiveHundred = big.NewInt(3500)
var fourteenThousand = big.NewInt(14000)

var minusFifty = big.NewInt(-50)
var minusSeventy = big.NewInt(-70)
var minusOneHundredTwenty = big.NewInt(-120)
var minusThreeThousandFiveHundred = big.NewInt(-3500)

func TestL2TCPaillier_Encrypt(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encVal, _, err := pk.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, zkp, err := pk.PartialDecryptL1(share, encVal)
		if err != nil {
			t.Error(err)
			return
		}
		if zkp.Verify(pk.Paillier, encVal, ds) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}

	if decrypted.Cmp(fifty) != 0 {
		t.Errorf("values are distinct: decrypted: %s and first value was %d", decrypted, fifty)
		return
	}
}

func TestL2TCPaillier_EncryptMinus(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encVal, _, err := pk.Encrypt(minusFifty)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, zkp, err := pk.PartialDecryptL1(share, encVal)
		if err != nil {
			t.Error(err)
			return
		}
		if zkp.Verify(pk.Paillier, encVal, ds) != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}

	if decrypted.Cmp(new(big.Int).Mod(minusFifty, pk.Paillier.N)) != 0 {
		t.Errorf("values are distinct:\ndecrypted: %s\nexpected: %s\nmodule: %s", decrypted, minusFifty, pk.Paillier.N)
		return
	}
}

func TestL2TCPaillier_AddL1(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encVal1, _, err := pk.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	encVal2, _, err := pk.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	encResul, err := pk.AddL1(encVal1, encVal2)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, zkp, err := pk.PartialDecryptL1(share, encResul)
		if err != nil {
			t.Error(err)
			return
		}
		if err := zkp.Verify(pk.Paillier, encResul, ds); err != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(oneHundredTwenty) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, oneHundredTwenty)
		return
	}
}

func TestL2TCPaillier_AddL1Negative(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	randoms := make([]*big.Int, len(keyShares))
	var randSum = new(big.Int)

	encryptedRandoms := make([]*l2fhe.EncryptedL1, len(keyShares))
	var encryptedRandSum *l2fhe.EncryptedL1

	pdRandSum := make([]*l2fhe.DecryptedShareL1, len(keyShares))
	var decryptedRandSum *big.Int

	for i := 0; i < len(keyShares); i++ {
		randoms[i], err = tcecdsa.RandomInRange(big.NewInt(-1000), new(big.Int))
		if err != nil {
			t.Error(err)
			return
		}
		randSum.Add(randSum, randoms[i])
		encryptedRandoms[i], _, err = pk.Encrypt(randoms[i])
		if err != nil {
			t.Error(err)
			return
		}
	}

	encryptedRandSum, err = pk.AddL1(encryptedRandoms...)
	if err != nil {
		t.Error(err)
	}

	for i, share := range keyShares {
		var zkp tcpaillier.ZKProof
		pdRandSum[i], zkp, err = pk.PartialDecryptL1(share, encryptedRandSum)
		if err != nil {
			t.Error(err)
			return
		}
		if err := zkp.Verify(pk.Paillier, encryptedRandSum, pdRandSum[i]); err != nil {
			t.Error(err)
			return
		}
	}
	decryptedRandSum, err = pk.CombineSharesL1(pdRandSum...)
	if err != nil {
		t.Error(err)
		return
	}

	randSum.Mul(randSum, big.NewInt(-2)).Mod(randSum, pk.Paillier.N)
	decryptedRandSum.Mul(decryptedRandSum, big.NewInt(-2)).Mod(decryptedRandSum, pk.Paillier.N)

	fmt.Printf("   random sum: %s\n", randSum)
	fmt.Printf("decrypted sum: %s\n", decryptedRandSum)

	if decryptedRandSum.Cmp(decryptedRandSum) != 0 {
		t.Errorf("values are not equal")
	}

}

func TestL2TCPaillier_MulConstL1(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encFifty, _, err := pk.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := pk.MulConstL1(encFifty, seventy)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, zkp, err := pk.PartialDecryptL1(share, encThreeThousandFiveHundred)
		if err != nil {
			t.Error(err)
			return
		}
		if err := zkp.Verify(pk.Paillier, encThreeThousandFiveHundred, ds); err != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(threeThousandFiveHundred) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, threeThousandFiveHundred)
		return
	}
}

func TestL2TCPaillier_MulConstL1Minus(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encFifty, _, err := pk.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := pk.MulConstL1(encFifty, minusSeventy)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL1, 0)
	for _, share := range keyShares {
		ds, zkp, err := pk.PartialDecryptL1(share, encThreeThousandFiveHundred)
		if err != nil {
			t.Error(err)
			return
		}
		if err := zkp.Verify(pk.Paillier, encThreeThousandFiveHundred, ds); err != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL1(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(new(big.Int).Mod(minusThreeThousandFiveHundred, pk.Paillier.N)) != 0 {
		t.Errorf("we decrypted %s, but sum value should have been %d", decrypted, minusThreeThousandFiveHundred)
		return
	}
}

func TestL2TCPaillier_Mul(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encFifty, _, err := pk.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	encSeventy, _, err := pk.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := pk.Mul(encFifty, encSeventy)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL2, 0)
	for _, share := range keyShares {
		ds, zkp, err := pk.PartialDecryptL2(share, encThreeThousandFiveHundred)
		if err != nil {
			t.Error(err)
			return
		}
		if err := zkp.Verify(pk.Paillier, encThreeThousandFiveHundred, ds); err != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL2(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(threeThousandFiveHundred) != 0 {
		t.Errorf("Error Decrypting:\nDecrypted = %s\n Expected = %s\n   Module = %s", decrypted, threeThousandFiveHundred, pk.Paillier.N)
		return
	}
}

func TestL2TCPaillier_AddL2(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encFifty, _, err := pk.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	encSeventy, _, err := pk.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := pk.Mul(encFifty, encSeventy)
	if err != nil {
		t.Error(err)
		return
	}

	encFourteenThousand, err := pk.AddL2(
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
		ds, zkp, err := pk.PartialDecryptL2(share, encFourteenThousand)
		if err != nil {
			t.Error(err)
			return
		}
		if err := zkp.Verify(pk.Paillier, encFourteenThousand, ds); err != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL2(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(fourteenThousand) != 0 {
		t.Errorf("Error Decrypting:\nDecrypted = %s\n Expected = %s\n   Module = %s", decrypted, threeThousandFiveHundred, pk.Paillier.N)
		return
	}
}

func TestL2TCPaillier_MulConstL2(t *testing.T) {
	pk, keyShares, err := l2fhe.NewKey(bitSize, l, k)
	if err != nil {
		t.Error(err)
		return
	}

	encFifty, _, err := pk.Encrypt(fifty)
	if err != nil {
		t.Error(err)
		return
	}

	encSeventy, _, err := pk.Encrypt(seventy)
	if err != nil {
		t.Error(err)
		return
	}

	encThreeThousandFiveHundred, err := pk.Mul(encFifty, encSeventy)
	if err != nil {
		t.Error(err)
		return
	}

	encFourteenThousand, err := pk.MulConstL2(encThreeThousandFiveHundred, four)
	if err != nil {
		t.Error(err)
		return
	}

	decShares := make([]*l2fhe.DecryptedShareL2, 0)
	for _, share := range keyShares {
		ds, zkp, err := pk.PartialDecryptL2(share, encFourteenThousand)
		if err != nil {
			t.Error(err)
			return
		}
		if err := zkp.Verify(pk.Paillier, encFourteenThousand, ds); err != nil {
			t.Error(err)
			return
		}
		decShares = append(decShares, ds)
	}

	decrypted, err := pk.CombineSharesL2(decShares...)
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted.Cmp(fourteenThousand) != 0 {
		t.Errorf("Error Decrypting:\nDecrypted = %s\n Expected = %s\n   Module = %s", decrypted, threeThousandFiveHundred, pk.Paillier.N)
		return
	}
}

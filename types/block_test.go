package types

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Moneeb919/go-blockchain/crypto"
	"github.com/Moneeb919/go-blockchain/util"
	"github.com/stretchr/testify/assert"
)

func TestHashBlock(t *testing.T) {
	block := util.RandomBlock()
	hash := HashBlock(block)
	fmt.Println(hex.EncodeToString(hash))
	assert.Equal(t, 32, len(hash))
}

func TestSignBlock(t *testing.T) {
	block := util.RandomBlock()
	pk := crypto.GeneratePrivateKey()
	pubKey := pk.Public()
	sig := SignBlock(pk, block)
	assert.Equal(t, 64, len(sig.Bytes()))
	assert.True(t, sig.Verify(pubKey, HashBlock(block)))
}

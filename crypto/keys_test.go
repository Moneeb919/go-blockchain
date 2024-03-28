package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	msg := []byte("foo bar baz")

	sig := privKey.Sign(msg)
	pubKey := privKey.Public()
	assert.True(t, sig.Verify(pubKey, msg))

	// test with invalid message
	assert.False(t, sig.Verify(pubKey, []byte("foo baz baz")))

	//test with invaid pubKey
	invalidPrivKey := GeneratePrivateKey()
	assert.False(t, sig.Verify(invalidPrivKey.Public(), msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed       = "69cab4a7ae8d62b697ee10e1c81387cce63c20328fb5846b61655763b46c9c31"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "3970f73ae883185753fdfdca96622b7c6d16de46"
	)
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
}

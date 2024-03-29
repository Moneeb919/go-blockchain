package types

import (
	"crypto/sha256"

	"github.com/Moneeb919/go-blockchain/crypto"

	"github.com/Moneeb919/go-blockchain/proto"
	pb "google.golang.org/protobuf/proto"
)

func SignBlock(pk *crypto.PrivateKey, b *proto.Block) *crypto.Signature {
	return pk.Sign(HashBlock(b))
}

// HashBlock returns a SHA256 of the header
func HashBlock(block *proto.Block) []byte {
	b, err := pb.Marshal(block)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(b)

	return hash[:] //hash is an array, so we convert it into a slice
}

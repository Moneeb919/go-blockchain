package types

import (
	"crypto/sha256"

	"github.com/Moneeb919/go-blockchain/crypto"
	"github.com/Moneeb919/go-blockchain/proto"
	pb "google.golang.org/protobuf/proto"
)

func SignTransaction(pk *crypto.PrivateKey, tx *proto.Transaction) *crypto.Signature {
	return pk.Sign(HashTransactions(tx))
}

func HashTransactions(tx *proto.Transaction) []byte {
	b, err := pb.Marshal(tx)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(b)
	return hash[:]
}

func VerifyTransactions(tx *proto.Transaction) bool {
	for _, input := range tx.Inputs {
		sig := crypto.SignatureFromBytes(input.Signature)
		pubKey := crypto.PublicKeyFromBytes(input.PublicKey)

		// we hash the transaction to generate the signature and then add that signature to the transaction which changes the transaction. So during verification we remove that signature as the transaction was hashed to generate the signature obviously before the signature was added//

		input.Signature = nil
		if !sig.Verify(pubKey, HashTransactions(tx)) {
			return false
		}
	}
	return true
}

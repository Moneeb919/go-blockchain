package util

import (
	randc "crypto/rand"
	"io"
	"math/rand"
	"time"

	"github.com/Moneeb919/go-blockchain/proto"
)

func RandomHash() []byte {
	hash := make([]byte, 32)
	_, err := io.ReadFull(randc.Reader, hash)
	if err != nil {
		panic(err)
	}
	return hash
}

func RandomBlock() *proto.Block {
	header := &proto.Header{
		Version:   1,
		Height:    int32(rand.Intn(1000) + 1),
		PrevHash:  RandomHash(),
		RootHash:  RandomHash(),
		Timestamp: time.Now().UnixNano(),
	}

	return &proto.Block{
		Header: header,
	}
}

package payment

import (
	"math/rand"
	"time"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateTxnRef(n int) string {
	rand.Seed(time.Now().UnixNano())
	ref := make([]byte, n)
	for i := range ref {
		ref[i] = letters[rand.Intn(len(letters))]
	}
	return string(ref)
}

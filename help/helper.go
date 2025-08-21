package help

import (
	"math/rand"
	"strings"
	"time"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz"

func init() {
	rand.New(rand.NewSource(time.Now().UnixNano()))
}

// Randomint generates a random int64 value between min and max parameters
func RandomInt(min, max int64) int64 {
	return min + rand.Int63n(max-min+1)
}

// RandomString generates a random string with lenght n
func RandomString(n int) string {
	var sb strings.Builder
	K := len(alphabet)
	for i := 0; i < n; i++ {
		c := alphabet[rand.Intn(K)]
		sb.WriteByte(c)
	}

	return sb.String()
}

// RandomEmail Creates a random email
func RandomEmail() string {
	user := RandomString(int(RandomInt(5, 8)))
	return user + "@gmail.com"

}

// RandomOwner generates a random owner name
func RandomOwner() int64 {
	return 1 //RandomString(4 + rand.Intn(10))
}

// RandomMoney generates a random money value from 0 to 1000
func RandomMoney() int64 {
	return (RandomInt(0, 1000))
}

// RandomCurrency returns a random value between these "EUR", "USD", "KRW", "JPY" currencies
func RandomCurreny() string {
	currencies := []string{"EUR", "USD", "KRW", "JPY"}
	n := len(currencies)
	return currencies[rand.Intn(n)]
}

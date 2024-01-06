package util

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var previousCookieSecret []byte
var currentCookieSecret []byte
var currentCookieSecretTime time.Time
var currentCookieSecretWriteLock sync.Mutex
var clientCookiePrefix = []byte("client")
var serverCookiePrefix = []byte("server")

const cookieRotationTime = time.Minute * 30

func getCookieSecret(previous bool) []byte {
	cookieSecretTimeCache := currentCookieSecretTime
	if time.Since(cookieSecretTimeCache) > cookieRotationTime {
		currentCookieSecretWriteLock.Lock()
		if currentCookieSecretTime == cookieSecretTimeCache {
			previousCookieSecret = currentCookieSecret
			currentCookieSecret = make([]byte, 64)
			_, err := rand.Read(currentCookieSecret)
			if err != nil {
				panic(err)
			}
			currentCookieSecretTime = time.Now()
		}
		currentCookieSecretWriteLock.Unlock()
	}

	if previous {
		return previousCookieSecret
	}
	return currentCookieSecret
}

func generateCookie(previous bool, data ...[]byte) []byte {
	hash := crypto.SHA256.New()
	cookieSecret := getCookieSecret(previous)
	if cookieSecret == nil {
		return nil
	}

	hash.Write(cookieSecret[0:32])
	for _, d := range data {
		hash.Write(d)
	}
	return hash.Sum(cookieSecret[32:64])
}

func GenerateClientCookie(previous bool, server string) []byte {
	return generateCookie(previous, clientCookiePrefix, []byte(server))[:8]
}

func GenerateServerCookie(previous bool, clientCookie []byte, wr dns.ResponseWriter) []byte {
	serverIp := ExtractIP(wr.LocalAddr())
	clientIp := ExtractIP(wr.RemoteAddr())
	return generateCookie(previous, serverCookiePrefix, serverIp, clientIp, clientCookie)[:8]
}

func CookieCompare(a []byte, b []byte) bool {
	if a == nil || b == nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

package util

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var currentCookieSecret = make([]byte, 16)
var currentCookieSecretTime time.Time
var currentCookieSecretWriteLock sync.Mutex
var cookiePrefix = []byte("foxDNS")
var clientCookiePrefix = []byte("client")
var serverCookiePrefix = []byte("server")

func getCookieSecret() []byte {
	cookieSecretTimeCache := currentCookieSecretTime
	if time.Since(cookieSecretTimeCache) > time.Hour {
		currentCookieSecretWriteLock.Lock()
		if currentCookieSecretTime == cookieSecretTimeCache {
			_, err := rand.Read(currentCookieSecret)
			if err != nil {
				panic(err)
			}
			currentCookieSecretTime = time.Now()
		}
		currentCookieSecretWriteLock.Unlock()
	}
	return currentCookieSecret
}

func generateCookie(data ...[]byte) []byte {
	hash := crypto.SHA3_256.New()
	hash.Write(cookiePrefix)
	for _, d := range data {
		hash.Write(d)
	}
	return hash.Sum(getCookieSecret())
}

func GenerateClientCookie(server string) []byte {
	return generateCookie(clientCookiePrefix, []byte(server))[:8]
}

func GenerateServerCookie(wr dns.ResponseWriter) []byte {
	serverIp := ExtractIP(wr.LocalAddr())
	clientIp := ExtractIP(wr.RemoteAddr())
	return generateCookie(serverCookiePrefix, serverIp, clientIp)[:32]
}

func CheckClientCookie(server string, cookie []byte) bool {
	return subtle.ConstantTimeCompare(cookie, GenerateClientCookie(server)) == 1
}

func CheckServerCookie(wr dns.ResponseWriter, cookie []byte) bool {
	return subtle.ConstantTimeCompare(cookie, GenerateServerCookie(wr)) == 1
}

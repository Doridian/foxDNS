package util

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"time"
)

var previousCookieSecret []byte
var currentCookieSecret []byte
var clientCookiePrefix = []byte("client")
var serverCookiePrefix = []byte("server")

const cookieRotationTime = time.Minute * 30

// These are specified by DNS and not adjustable
const ClientCookieLength = 8
const MinServerCookieLength = 8

// This length can be adjusted between 8 and 32
const ServerCookieLength = 8

var cookieRotateTicket = time.NewTicker(cookieRotationTime)

func init() {
	rotateCookieSecret()

	go func() {
		for {
			<-cookieRotateTicket.C
			rotateCookieSecret()
		}
	}()
}

func rotateCookieSecret() {
	previousCookieSecret = currentCookieSecret
	currentCookieSecret = make([]byte, 64)
	_, err := rand.Read(currentCookieSecret)
	if err != nil {
		panic(err)
	}
}

func getCookieSecret(previous bool) []byte {
	if previous {
		return previousCookieSecret
	}
	return currentCookieSecret
}

func generateCookie(previous bool, len int, data ...[]byte) []byte {
	hash := sha256.New()
	cookieSecret := getCookieSecret(previous)
	if cookieSecret == nil {
		return nil
	}

	hash.Write(cookieSecret[0:32])
	for _, d := range data {
		log.Printf("%v", d)
		hash.Write(d)
	}
	hash.Write(cookieSecret[32:64])
	return hash.Sum(nil)[:len]
}

func GenerateClientCookie(previous bool, server string) []byte {
	return generateCookie(previous, ClientCookieLength, clientCookiePrefix, []byte(server))
}

func GenerateServerCookie(previous bool, clientCookie []byte, wr Addressable) []byte {
	serverIp := ExtractIP(wr.LocalAddr())
	clientIp := ExtractIP(wr.RemoteAddr())
	return generateCookie(previous, ServerCookieLength, serverCookiePrefix, serverIp, clientIp, clientCookie)
}

func CookieCompare(a []byte, b []byte) bool {
	if a == nil || b == nil || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

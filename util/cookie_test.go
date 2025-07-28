package util_test

import (
	"log"
	"net"
	"testing"

	"github.com/Doridian/foxDNS/util"
	"github.com/stretchr/testify/assert"
)

func TestGenerateClientCookie(t *testing.T) {
	cookie := util.GenerateClientCookie(true, "test-client")
	assert.Nil(t, cookie)
	cookie = util.GenerateClientCookie(false, "test-client")
	assert.NotEmpty(t, cookie)
	assert.Len(t, cookie, 8)
	cookie2 := util.GenerateClientCookie(false, "test-client2")
	assert.NotEmpty(t, cookie2)
	log.Printf("Cookie %v %v", cookie, cookie2)
	assert.NotElementsMatch(t, cookie, cookie2)
}

func TestGenerateServerCookie(t *testing.T) {
	addressable := &util.DummyAddressable{
		RemoteAddress: &net.TCPAddr{IP: net.IPv4(10, 99, 3, 4), Port: 12345},
	}

	clientCookie := util.GenerateServerCookie(false, []byte("test-client"), addressable)
	assert.NotEmpty(t, clientCookie)
	assert.Len(t, clientCookie, 8)
}

func TestCookieCompare(t *testing.T) {
	cookie1 := util.GenerateClientCookie(false, "test-client")
	cookie2 := util.GenerateClientCookie(false, "test-client2")
	assert.False(t, util.CookieCompare(cookie1, cookie2))
	assert.True(t, util.CookieCompare(cookie1, cookie1))
	assert.False(t, util.CookieCompare(nil, cookie1))
	assert.False(t, util.CookieCompare(cookie1, nil))
	assert.False(t, util.CookieCompare(nil, nil))
}

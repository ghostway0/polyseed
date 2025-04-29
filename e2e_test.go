package polyseed_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"

	"github.com/ghostway0/polyseed"
)

type RWPair struct {
	reader io.Reader
	writer io.Writer
}

func (rw *RWPair) Read(p []byte) (n int, err error)  { return rw.reader.Read(p) }
func (rw *RWPair) Write(p []byte) (n int, err error) { return rw.writer.Write(p) }

func TestFullPAKEExchange_Success(t *testing.T) {
	ctx, err := polyseed.NewCryptoContext()
	if err != nil {
		t.Fatalf("failed to create crypto context: %v", err)
	}

	reader1, writer1 := io.Pipe()
	reader2, writer2 := io.Pipe()

	clientRW := &RWPair{reader: reader2, writer: writer1}
	serverRW := &RWPair{reader: reader1, writer: writer2}

	password := []byte("hunter2")
	var clientID [16]byte
	var serverID [16]byte
	rand.Read(clientID[:])
	rand.Read(serverID[:])

	var wg sync.WaitGroup
	var serverErr, clientErr error
	var serverKey, clientKey []byte

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer writer2.Close()
		defer reader1.Close()
		serverKey, serverErr = polyseed.Server(ctx, serverRW, serverID, password)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer writer1.Close()
		defer reader2.Close()
		clientKey, clientErr = polyseed.Client(ctx, clientRW, clientID, password)
	}()

	wg.Wait()

	if serverErr == nil && clientErr == nil {
		if !bytes.Equal(serverKey, clientKey) {
			t.Errorf("Derived keys do not match!\nServer: %x\nClient: %x", serverKey, clientKey)
		}
	} else {
		t.Errorf("server: %v client: %v", serverErr, clientErr)
	}
}

func TestFullPAKEExchange_WrongPassword(t *testing.T) {
	ctx, err := polyseed.NewCryptoContext()
	if err != nil {
		t.Fatalf("failed to create crypto context: %v", err)
	}

	reader1, writer1 := io.Pipe()
	reader2, writer2 := io.Pipe()

	clientRW := &RWPair{reader: reader2, writer: writer1}
	serverRW := &RWPair{reader: reader1, writer: writer2}

	var clientID [16]byte
	var serverID [16]byte
	rand.Read(clientID[:])
	rand.Read(serverID[:])

	var wg sync.WaitGroup
	var serverErr, clientErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer writer2.Close()
		defer reader1.Close()
		_, serverErr = polyseed.Server(ctx, serverRW, serverID, []byte("*******"))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer writer1.Close()
		defer reader2.Close()
		_, clientErr = polyseed.Client(ctx, clientRW, clientID, []byte("hunter2"))
	}()

	wg.Wait()

	if serverErr == nil || clientErr == nil {
		t.Error("Persuasion succeeded")
	}
}

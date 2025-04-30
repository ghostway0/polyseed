package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/ghostway0/polyseed"
)

func main() {
	ctx, err := polyseed.NewCryptoContext()
	if err != nil {
		log.Fatalf("ctx: %v", err)
	}

	password := make([]byte, 16)
	if _, err := rand.Read(password); err != nil {
		log.Fatalf("password gen: %v", err)
	}

	var serverID [16]byte
	if _, err := rand.Read(serverID[:]); err != nil {
		log.Fatalf("server ID: %v", err)
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// link = base64(ip:port|password)
	linkData := fmt.Sprintf("%s|%s", addr, base64.StdEncoding.EncodeToString(password))

	link := base64.StdEncoding.EncodeToString([]byte(linkData))
	fmt.Println(link)

	var key []byte
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		defer conn.Close()

		key, err = polyseed.Server(ctx, conn, serverID, password)
		if err == nil {
			break
		}

		log.Printf("%v", err)
	}

	fmt.Println(hex.EncodeToString(key))
}

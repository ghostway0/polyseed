package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"crypto/rand"

	"golang.org/x/term"

	"github.com/ghostway0/polyseed"
)

func main() {
	link, err := term.ReadPassword(int(os.Stdin.Fd()))

	decoded, err := base64.StdEncoding.DecodeString(string(link))
	if err != nil {
		log.Fatalf("decode link: %v", err)
	}

	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		log.Fatalf("invalid link format")
	}


	addr := parts[0]
	password, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		log.Fatalf("decode password: %v", err)
	}

	ctx, err := polyseed.NewCryptoContext()
	if err != nil {
		log.Fatalf("ctx: %v", err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	var clientID [16]byte
	if _, err := rand.Read(clientID[:]); err != nil {
		log.Fatalf("client ID: %v", err)
	}

	key, err := polyseed.Client(ctx, conn, clientID, password)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Println(hex.EncodeToString(key))
}

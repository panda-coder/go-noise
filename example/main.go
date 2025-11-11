package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/panda-coder/go-noise/noise"
)

func runServer() {
	fmt.Println("=== Noise Protocol Go Simple Chat Example (NX Server) ===")
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Println("Listening on :8080")

	conn, err := listener.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Client connected")

	// 1. Setup
	n, err := noise.New()
	if err != nil {
		log.Fatal(err)
	}

	// --- Handshake ---
	responder, err := n.HandshakeState("Noise_NX_25519_ChaChaPoly_BLAKE2s", n.Constants.NOISE_ROLE_RESPONDER)
	if err != nil {
		log.Fatal(err)
	}

	err = responder.Start()
	if err != nil {
		log.Fatal(err)
	}

	// Responder <- Initiator
	buf := make([]byte, 32)
	_, err = conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	_, err = responder.ReadMessage(buf)
	if err != nil {
		log.Fatal(err)
	}

	// Responder -> Initiator
	msg, err := responder.WriteMessage(nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(msg)
	if err != nil {
		log.Fatal(err)
	}

	// --- Split ---
	responderCipherSend, responderCipherRecv, err := responder.Split()
	if err != nil {
		log.Fatal(err)
	}

	// --- Chat Simulation ---
	fmt.Println("\n---")
	fmt.Println("Secure Chat Started")
	fmt.Println("Type your message and press Enter. Type 'quit' to exit.")

	go readAndPrint(responderCipherRecv, conn)
	writeAndEncrypt(responderCipherSend, conn)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <server|client>")
		return
	}

	mode := os.Args[1]

	switch mode {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		fmt.Println("Invalid mode. Use 'server' or 'client'.")
	}
}



func readAndPrint(cs *noise.CipherState, conn net.Conn) {
	reader := bufio.NewReader(conn)
	for {
		buf, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("Connection closed")
				break
			}
			log.Fatal(err)
		}

		decrypted, err := cs.DecryptWithAd(nil, buf[:len(buf)-1])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Friend: %s\n", string(decrypted))
	}
}

func writeAndEncrypt(cs *noise.CipherState, conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("You: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if strings.ToLower(input) == "quit" {
			break
		}

		encrypted, err := cs.EncryptWithAd(nil, []byte(input))
		if err != nil {
			log.Fatal(err)
		}
		_, err = conn.Write(append(encrypted, '\n'))
		if err != nil {
			log.Fatal(err)
		}
	}
}

func runClient() {
	fmt.Println("=== Noise Protocol Go Simple Chat Example (NX Client) ===")
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Connected to server")

	// 1. Setup
	n, err := noise.New()
	if err != nil {
		log.Fatal(err)
	}

	// --- Handshake ---
	initiator, err := n.HandshakeState("Noise_NX_25519_ChaChaPoly_BLAKE2s", n.Constants.NOISE_ROLE_INITIATOR)
	if err != nil {
		log.Fatal(err)
	}

	err = initiator.Start()
	if err != nil {
		log.Fatal(err)
	}

	// Initiator -> Responder
	msg, err := initiator.WriteMessage(nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(msg)
	if err != nil {
		log.Fatal(err)
	}

	// Initiator <- Responder
	buf := make([]byte, 32)
	_, err = conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	_, err = initiator.ReadMessage(buf)
	if err != nil {
		log.Fatal(err)
	}

	// --- Split ---
	initiatorCipherSend, initiatorCipherRecv, err := initiator.Split()
	if err != nil {
		log.Fatal(err)
	}

	// --- Chat Simulation ---
	fmt.Println("\n---")
	fmt.Println("Secure Chat Started")
	fmt.Println("Type your message and press Enter. Type 'quit' to exit.")

	go readAndPrint(initiatorCipherRecv, conn)
	writeAndEncrypt(initiatorCipherSend, conn)
}


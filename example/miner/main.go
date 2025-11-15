package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)
func main() {
	host := flag.String("host", "localhost", "Pool host address")
	port := flag.Int("port", 2000, "Pool port")
	worker := flag.String("worker", "go-miner.worker", "Worker name")
	hashrate := flag.Float64("hashrate", 0.000250, "Hashrate in GH/s (default: 250kH/s)")
	useEncryption := flag.Bool("encryption", true, "Enable Noise protocol encryption")
	useEllSwift := flag.Bool("ellswift", false, "Use ElligatorSwift (Stratum V2 spec). Default is X25519 for Python pool compatibility")
	flag.Parse()

	deviceInfo := DeviceInfo{
		SpeedGHps:       *hashrate,
		Vendor:          "golang",
		HardwareVersion: "v1.0",
		Firmware:        "go-miner",
		DeviceID:        *worker,
	}

	// Difficulty 1 target (Bitcoin difficulty 1)
	// 0x00000000FFFF0000000000000000000000000000000000000000000000000000
	diff1Target := make([]byte, 32)
	diff1Target[2] = 0xFF
	diff1Target[3] = 0xFF

	m := NewMiner(*worker, deviceInfo, diff1Target)

	fmt.Printf("Starting miner: %s\n", *worker)
	fmt.Printf("Connecting to: %s:%d\n", *host, *port)
	fmt.Printf("Hashrate: %.6f GH/s\n", *hashrate)
	fmt.Printf("Encryption: %v\n", *useEncryption)
	if *useEncryption {
		if *useEllSwift {
			fmt.Printf("Protocol: ElligatorSwift (Stratum V2 spec)\n")
		} else {
			fmt.Printf("Protocol: X25519 (Standard Noise, compatible with Python pool)\n")
		}
	}

	if err := m.Connect(*host, *port, *useEncryption, *useEllSwift); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down miner...")
		m.Close()
		os.Exit(0)
	}()

	if err := m.ReceiveLoop(); err != nil {
		log.Fatalf("Receive loop error: %v", err)
	}
}
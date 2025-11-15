package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"github.com/panda-coder/go-noise/sv2"
)

type MinerState int

const (
	StateInit MinerState = iota
	StateConnectionSetup
	StateChannelOpen
	StateMining
)

type DeviceInfo struct {
	SpeedGHps       float64
	Vendor          string
	HardwareVersion string
	Firmware        string
	DeviceID        string
}

type MiningJob struct {
	UID         uint32
	Version     uint32
	MerkleRoot  []byte
	DiffTarget  []byte
	StartedAt   time.Time
	IsCancelled bool
	mu          sync.Mutex
}

func (j *MiningJob) Cancel() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.IsCancelled = true
}

func (j *MiningJob) Cancelled() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.IsCancelled
}

type MiningSession struct {
	PrevHash    []byte
	MinNTime    uint32
	NBits       uint32
	CurrTarget  []byte
	JobRegistry map[uint32]*MiningJob
	mu          sync.RWMutex
}

func NewMiningSession() *MiningSession {
	return &MiningSession{
		JobRegistry: make(map[uint32]*MiningJob),
	}
}

func (s *MiningSession) AddJob(job *MiningJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.JobRegistry[job.UID] = job
}

func (s *MiningSession) GetJob(jobID uint32) *MiningJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.JobRegistry[jobID]
}

func (s *MiningSession) RetireAllJobs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, job := range s.JobRegistry {
		job.Cancel()
	}
}

func (s *MiningSession) SetPrevHash(prevHash []byte, minNTime, nbits uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PrevHash = prevHash
	s.MinNTime = minNTime
	s.NBits = nbits
}

func (s *MiningSession) SetTarget(target []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrTarget = target
}

type MiningChannel struct {
	ChannelID uint32
	Session   *MiningSession
}

type Connection struct {
	conn          net.Conn
	sendCipher    *sv2.CipherState
	recvCipher    *sv2.CipherState
	sendLock      sync.Mutex
	recvLock      sync.Mutex
	isEncrypted   bool
	minerID       string
	useEllSwift   bool // true for ElligatorSwift (64-byte keys), false for X25519 (32-byte keys)
}

func NewConnection(host string, port int, minerID string, useEllSwift bool) (*Connection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	return &Connection{
		conn:        conn,
		isEncrypted: false,
		minerID:     minerID,
		useEllSwift: useEllSwift,
	}, nil
}
func (c *Connection) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

 // PerformHandshake performs the Noise_NX handshake with ElligatorSwift or X25519 encoding
 //
 // Supports two protocols:
 //   1. ElligatorSwift (Stratum V2 spec): 64-byte public keys
 //      - Act 1: 64 bytes, Act 2: 144 bytes
 //   2. X25519 (Standard Noise): 32-byte public keys
 //      - Act 1: 32 bytes, Act 2: 96 bytes
 //
 // The protocol is selected via the useEllSwift field in the Connection struct.
func (c *Connection) PerformHandshake() error {
	if c.useEllSwift {
		log.Printf("[%s] Using ElligatorSwift handshake (Stratum V2 spec)", c.minerID)
		return c.performHandshakeEllSwift()
	} else {
		log.Printf("[%s] Using X25519 handshake (Standard Noise)", c.minerID)
		return c.performHandshakeX25519()
	}
}

// performHandshakeEllSwift implements the Stratum V2 handshake with ElligatorSwift
func (c *Connection) performHandshakeEllSwift() error {
	log.Printf("[%s] Starting Noise handshake", c.minerID)
	protocolName := "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"
	log.Printf("[%s] Protocol: %s", c.minerID, protocolName)
	h := sv2.HASH([]byte(protocolName))
	ck := h[:]
	h = sv2.HASH(h[:])

	initiatorEphemeral, err := sv2.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	ephemeralPubKey := initiatorEphemeral.PublicKey()
	act1Message := ephemeralPubKey

	log.Printf("[%s] Generated ephemeral keypair, public key length: %d bytes", c.minerID, len(ephemeralPubKey))

	h = sv2.HASH(append(h, ephemeralPubKey...))
	h = sv2.HASH(append(h, []byte{}...))

	// Wrap Act1 message with 2-byte length prefix (like Python Connection.wrap)
	act1Length := uint16(len(act1Message))
	act1WithLength := make([]byte, 2+len(act1Message))
	binary.LittleEndian.PutUint16(act1WithLength[0:2], act1Length)
	copy(act1WithLength[2:], act1Message)

	log.Printf("[%s] Sending Act 1: %d bytes (payload) + 2 bytes (length prefix) = %d bytes total", c.minerID, act1Length, len(act1WithLength))
	_, err = c.conn.Write(act1WithLength)
	if err != nil {
		return fmt.Errorf("failed to send Act 1: %w", err)
	}
	log.Printf("[%s] Act 1 sent successfully", c.minerID)

	// Read Act2 with 2-byte length prefix
	lengthBytes := make([]byte, 2)
	_, err = io.ReadFull(c.conn, lengthBytes)
	if err != nil {
		return fmt.Errorf("failed to receive Act 2 length: %w", err)
	}
	act2Length := binary.LittleEndian.Uint16(lengthBytes)

	log.Printf("[%s] Received Act 2 length: %d bytes", c.minerID, act2Length)

	// Expected length: 64 bytes (ElligatorSwift ephemeral) + 80 bytes (encrypted static + MAC) = 144 bytes
	// If we get 96 bytes, it's likely X25519 (32 bytes) instead of ElligatorSwift (64 bytes)
	if act2Length == 96 {
		log.Printf("[%s] WARNING: Received 96 bytes for Act 2, expected 144 bytes", c.minerID)
		log.Printf("[%s] The pool is likely using X25519 (32-byte keys) instead of ElligatorSwift (64-byte keys)", c.minerID)
		log.Printf("[%s] Go miner implements Stratum V2 spec with ElligatorSwift, but Python pool simulator uses standard X25519", c.minerID)
		return fmt.Errorf("handshake protocol mismatch: received %d bytes, expected 144 bytes (ElligatorSwift). Pool appears to use X25519 instead", act2Length)
	}

	if act2Length != 144 {
		return fmt.Errorf("unexpected Act 2 length: got %d bytes, expected 144 bytes", act2Length)
	}

	act2Message := make([]byte, act2Length)
	_, err = io.ReadFull(c.conn, act2Message)
	if err != nil {
		return fmt.Errorf("failed to receive Act 2: %w", err)
	}

	log.Printf("[%s] Successfully received Act 2 message", c.minerID)

	responderEphemeral := act2Message[:64]
	h = sv2.HASH(append(h, responderEphemeral...))

	eeShared, err := sv2.V2ECDHEllSwift(
		initiatorEphemeral,
		responderEphemeral,
		true,
	)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}

	ck, temp := sv2.HKDF(ck, eeShared)
	var key [32]byte
	copy(key[:], temp)

	cs := &sv2.CipherState{}
	cs.InitializeKey(key)

	encryptedStatic := act2Message[64:144]
	staticPubKey, err := cs.DecryptWithAd(h, encryptedStatic)
	if err != nil {
		return fmt.Errorf("failed to decrypt static key: %w", err)
	}
	h = sv2.HASH(append(h, encryptedStatic...))

	esShared, err := sv2.V2ECDHEllSwift(
		initiatorEphemeral,
		staticPubKey,
		true,
	)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}

	ck, temp = sv2.HKDF(ck, esShared)
	copy(key[:], temp)
	cs.InitializeKey(key)

	encryptedSignature := act2Message[144:170]
	_, err = cs.DecryptWithAd(h, encryptedSignature)
	if err != nil {
		return fmt.Errorf("failed to decrypt signature: %w", err)
	}

	tempK1, tempK2 := sv2.HKDF(ck, []byte{})

	c.sendCipher = &sv2.CipherState{}
	c.recvCipher = &sv2.CipherState{}

	var sendKey, recvKey [32]byte
	copy(sendKey[:], tempK1)
	copy(recvKey[:], tempK2)

	c.sendCipher.InitializeKey(sendKey)
	c.recvCipher.InitializeKey(recvKey)
	c.isEncrypted = true

	log.Printf("[%s] ✓ Noise handshake completed successfully!", c.minerID)
	return nil
}

// performHandshakeX25519 implements the standard Noise_NX handshake with X25519 (32-byte keys)
// This is compatible with the Python pool simulator
func (c *Connection) performHandshakeX25519() error {
	log.Printf("[%s] Starting X25519 Noise handshake", c.minerID)
	protocolName := "NX"
	log.Printf("[%s] Protocol: %s", c.minerID, protocolName)

	// Initialize handshake state with Blake2s
	h, _ := blake2s.New256(nil)
	h.Write([]byte(protocolName))
	hSum := h.Sum(nil)
	ck := make([]byte, 32)
	copy(ck, hSum)

	h.Reset()
	h.Write(hSum)
	hSum = h.Sum(nil)

	// Mix in empty prologue
	h.Reset()
	h.Write(hSum)
	hSum = h.Sum(nil)

	// Generate ephemeral keypair
	var ephemeralPrivate [32]byte
	if _, err := rand.Read(ephemeralPrivate[:]); err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to compute ephemeral public key: %w", err)
	}

	log.Printf("[%s] Generated ephemeral keypair, public key length: %d bytes", c.minerID, len(ephemeralPublic))

	// Update handshake hash: h = HASH(h || e.public_key)
	h.Reset()
	h.Write(hSum)
	h.Write(ephemeralPublic)
	hSum = h.Sum(nil)

	// Send Act1: ephemeral public key with 2-byte length prefix
	act1Length := uint16(len(ephemeralPublic))
	act1WithLength := make([]byte, 2+len(ephemeralPublic))
	binary.LittleEndian.PutUint16(act1WithLength[0:2], act1Length)
	copy(act1WithLength[2:], ephemeralPublic)

	log.Printf("[%s] Sending Act 1: %d bytes (payload) + 2 bytes (length prefix) = %d bytes total", c.minerID, act1Length, len(act1WithLength))
	if _, err := c.conn.Write(act1WithLength); err != nil {
		return fmt.Errorf("failed to send Act 1: %w", err)
	}
	log.Printf("[%s] Act 1 sent successfully", c.minerID)

	// Read Act2: responder ephemeral + encrypted static key
	log.Printf("[%s] Waiting for Act 2...", c.minerID)
	// Add a read deadline so we don't block indefinitely during the handshake
	if err := c.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[%s] Warning: failed to set read deadline: %v", c.minerID, err)
	}
	// Clear the deadline after this read sequence
	defer func() {
		_ = c.conn.SetReadDeadline(time.Time{})
	}()

	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, lengthBytes); err != nil {
		// Provide more context in the error for debugging
		return fmt.Errorf("failed to receive Act 2 length (waiting for 2 bytes): %w", err)
	}
	act2Length := binary.LittleEndian.Uint16(lengthBytes)

	log.Printf("[%s] Received Act 2 length: %d bytes", c.minerID, act2Length)

	// Expected: 32 bytes (responder ephemeral) + 48 bytes (encrypted static + MAC) + 16 bytes (encrypted signature + MAC) = 96 bytes
	// The Python pool uses dissononce NX pattern which includes: <- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
	if act2Length != 96 {
		return fmt.Errorf("unexpected Act 2 length for X25519: got %d bytes, expected 96 bytes", act2Length)
	}

	act2Message := make([]byte, act2Length)
	if _, err := io.ReadFull(c.conn, act2Message); err != nil {
		return fmt.Errorf("failed to receive Act 2 (waiting for %d bytes): %w", act2Length, err)
	}

	log.Printf("[%s] Successfully received Act 2 message", c.minerID)

	// Extract responder ephemeral key
	responderEphemeral := act2Message[:32]
	h.Reset()
	h.Write(hSum)
	h.Write(responderEphemeral)
	hSum = h.Sum(nil)

	// Perform ECDH: ee
	eeShared, err := curve25519.X25519(ephemeralPrivate[:], responderEphemeral)
	if err != nil {
		return fmt.Errorf("ECDH (ee) failed: %w", err)
	}

	// HKDF to derive key
	ck, temp := hkdf(ck, eeShared)
	var key [32]byte
	copy(key[:], temp)

	// Create cipher for decrypting static key
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt static key (32 bytes + 16 bytes MAC)
	encryptedStatic := act2Message[32:80]
	nonce := make([]byte, 12) // Nonce = 0 for first message

	// Debug: log key, nonce, hash (AD), and encrypted payload to help diagnose authentication failures.
	// NOTE: These logs contain sensitive key material. Remove or restrict in production.
	log.Printf("[%s] Debug: decrypting static key. key=%x", c.minerID, key[:])
	log.Printf("[%s] Debug: nonce=%x hSum=%x encryptedStatic(len=%d)=%x", c.minerID, nonce, hSum, len(encryptedStatic), encryptedStatic)

	staticPubKey, err := aead.Open(nil, nonce, encryptedStatic, hSum)
	if err != nil {
		// Additional debug on failure before returning
		log.Printf("[%s] Debug: aead.Open failed: %v", c.minerID, err)
		log.Printf("[%s] Debug: key=%x nonce=%x hSum=%x encryptedStatic=%x", c.minerID, key[:], nonce, hSum, encryptedStatic)
		return fmt.Errorf("failed to decrypt static key: %w", err)
	}
	log.Printf("[%s] Debug: decrypted static key (%d bytes): %x", c.minerID, len(staticPubKey), staticPubKey)

	h.Reset()
	h.Write(hSum)
	h.Write(encryptedStatic)
	hSum = h.Sum(nil)
	log.Printf("[%s] Debug: updated hSum after including encryptedStatic: %x", c.minerID, hSum)

	// Perform ECDH: es
	esShared, err := curve25519.X25519(ephemeralPrivate[:], staticPubKey)
	if err != nil {
		return fmt.Errorf("ECDH (es) failed: %w", err)
	}

	// HKDF to derive key for signature decryption
	ck, temp = hkdf(ck, esShared)
	copy(key[:], temp)

	// Create cipher for decrypting signature
	aead, err = chacha20poly1305.New(key[:])
	if err != nil {
		return fmt.Errorf("failed to create cipher for signature: %w", err)
	}

	// Decrypt signature message (0 bytes payload + 16 bytes MAC for localhost)
	encryptedSignature := act2Message[80:96]
	binary.LittleEndian.PutUint64(nonce[4:], 0) // Reset nonce counter to 0 for the new cipher
	signature, err := aead.Open(nil, nonce, encryptedSignature, hSum)
	if err != nil {
		return fmt.Errorf("failed to decrypt signature: %w", err)
	}

	// Update hash with encrypted signature
	h.Reset()
	h.Write(hSum)
	h.Write(encryptedSignature)
	hSum = h.Sum(nil)

	log.Printf("[%s] Decrypted signature: %d bytes (expected 0 for localhost)", c.minerID, len(signature))

	// Split to get send and receive keys
	tempK1, tempK2 := hkdf(ck, []byte{})

	var sendKey, recvKey [32]byte
	copy(sendKey[:], tempK1)
	copy(recvKey[:], tempK2)

	// Initialize cipher states
	c.sendCipher = &sv2.CipherState{}
	c.recvCipher = &sv2.CipherState{}
	c.sendCipher.InitializeKey(sendKey)
	c.recvCipher.InitializeKey(recvKey)
	c.isEncrypted = true

	log.Printf("[%s] ✓ X25519 handshake completed successfully!", c.minerID)
	return nil
}

// hkdf implements HKDF-BLAKE2s as used in the Noise protocol
func hkdf(chainingKey, inputKeyMaterial []byte) ([]byte, []byte) {
	// temp_key = HMAC-BLAKE2s(chaining_key, input_key_material)
	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, chainingKey)
	mac.Write(inputKeyMaterial)
	tempKey := mac.Sum(nil)

	// output1 = HMAC-BLAKE2s(temp_key, 0x01)
	mac1 := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, tempKey)
	mac1.Write([]byte{0x01})
	output1 := mac1.Sum(nil)

	// output2 = HMAC-BLAKE2s(temp_key, output1 || 0x02)
	mac2 := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, tempKey)
	mac2.Write(output1)
	mac2.Write([]byte{0x02})
	output2 := mac2.Sum(nil)

	return output1, output2
}

func (c *Connection) SendFrame(frame *sv2.Frame) error {
	c.sendLock.Lock()
	defer c.sendLock.Unlock()

	// Prepare common variables so the final write (in the suffix) can use them
	var frameBytes []byte
	var err error

	if c.isEncrypted {
		// Python pool encryption format: encrypt entire frame, then wrap with 2-byte length
		frameBytes, err = frame.ToBytes()
		if err != nil {
			return err
		}

		encryptedFrame := c.sendCipher.EncryptWithAd(nil, frameBytes)

		// Wrap with 2-byte length prefix
		length := uint16(len(encryptedFrame))
		lengthBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(lengthBytes, length)

		_, err = c.conn.Write(lengthBytes)
		if err != nil {
			return err
		}

		// Set frameBytes to the encrypted frame so the common write at the end sends it
		frameBytes = encryptedFrame
	} else {
		// Unencrypted mode: 2-byte length prefix + frame
		frameBytes, err = frame.ToBytes()
		if err != nil {
			return err
		}

		length := uint16(len(frameBytes))
		lengthBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(lengthBytes, length)

		_, err = c.conn.Write(lengthBytes)
	}
	if err != nil {
		return err
	}

	_, err = c.conn.Write(frameBytes)
	return err
}

func (c *Connection) SendMessage(msg sv2.Message) error {
	frame, err := msg.ToFrame()
	if err != nil {
		return err
	}
	return c.SendFrame(frame)
}

func (c *Connection) ReceiveFrame() (*sv2.Frame, error) {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()

	// Read 2-byte length prefix
	lengthBytes := make([]byte, 2)
	_, err := io.ReadFull(c.conn, lengthBytes)
	if err != nil {
		return nil, err
	}

	length := binary.LittleEndian.Uint16(lengthBytes)

	// Read the frame/encrypted data
	data := make([]byte, length)
	_, err = io.ReadFull(c.conn, data)
	if err != nil {
		return nil, err
	}

	if c.isEncrypted {
		// Python pool format: decrypt the entire frame
		frameBytes, err := c.recvCipher.DecryptWithAd(nil, data)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt frame: %w", err)
		}

		return sv2.ParseFrame(frameBytes)
	}

	// Unencrypted mode
	return sv2.ParseFrame(data)
}

type Miner struct {
	Name        string
	DeviceInfo  DeviceInfo
	Diff1Target []byte

	State   MinerState
	Conn    *Connection
	Channel *MiningChannel

	CurrentJob *MiningJob
	stopMining chan struct{}
	miningWg   sync.WaitGroup

	reqIDCounter uint32
	reqIDMu      sync.Mutex
}

func NewMiner(name string, deviceInfo DeviceInfo, diff1Target []byte) *Miner {
	return &Miner{
		Name:         name,
		DeviceInfo:   deviceInfo,
		Diff1Target:  diff1Target,
		State:        StateInit,
		stopMining:   make(chan struct{}),
		reqIDCounter: 1,
	}
}

func (m *Miner) nextReqID() uint32 {
	m.reqIDMu.Lock()
	defer m.reqIDMu.Unlock()
	id := m.reqIDCounter
	m.reqIDCounter++
	return id
}

func (m *Miner) Connect(host string, port int, useEncryption bool, useEllSwift bool) error {
	conn, err := NewConnection(host, port, m.Name, useEllSwift)
	if err != nil {
		return fmt.Errorf("failed to create connection: %w", err)
	}

	m.Conn = conn
	fmt.Printf("[%s] Connected to %s:%d\n", m.Name, host, port)

	if useEncryption {
		fmt.Printf("[%s] Performing Noise handshake...\n", m.Name)
		if err := m.Conn.PerformHandshake(); err != nil {
			return fmt.Errorf("handshake failed: %w", err)
		}
		fmt.Printf("[%s] Handshake successful\n", m.Name)
	} else {
		fmt.Printf("[%s] Encryption disabled (unencrypted mode)\n", m.Name)
	}

	return m.setupConnection(host, port)
}

func (m *Miner) setupConnection(host string, port int) error {
	msg := sv2.SetupConnection{
		Protocol:        0,
		MinVersion:      2,
		MaxVersion:      2,
		Flags:           0,
		EndpointHost:    host,
		EndpointPort:    uint16(port),
		Vendor:          m.DeviceInfo.Vendor,
		HardwareVersion: m.DeviceInfo.HardwareVersion,
		Firmware:        m.DeviceInfo.Firmware,
		DeviceID:        m.DeviceInfo.DeviceID,
	}

	fmt.Printf("[%s] Sending SetupConnection\n", m.Name)
	return m.Conn.SendMessage(&msg)
}

func (m *Miner) openMiningChannel() error {
	nominalHashRate := uint32(m.DeviceInfo.SpeedGHps * 1e9)

	msg := sv2.OpenStandardMiningChannel{
		ReqID:           m.nextReqID(),
		UserIdentity:    m.Name,
		NominalHashRate: nominalHashRate,
		MaxTarget:       m.Diff1Target,
	}

	fmt.Printf("[%s] Sending OpenStandardMiningChannel\n", m.Name)
	return m.Conn.SendMessage(&msg)
}

func (m *Miner) ReceiveLoop() error {
	for {
		frame, err := m.Conn.ReceiveFrame()
		if err != nil {
			if err == io.EOF {
				fmt.Printf("[%s] Connection closed by server\n", m.Name)
				return nil
			}
			if isConnectionResetError(err) {
				fmt.Printf("[%s] Connection reset by peer\n", m.Name)
				return nil
			}
			return fmt.Errorf("receive error: %w", err)
		}

		msg, err := m.parseMessage(frame)
		if err != nil {
			fmt.Printf("[%s] Error parsing message: %v\n", m.Name, err)
			continue
		}

		if err := m.handleMessage(msg); err != nil {
			fmt.Printf("[%s] Error handling message: %v\n", m.Name, err)
		}
	}
}

func isConnectionResetError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe")
}

func (m *Miner) parseMessage(frame *sv2.Frame) (sv2.Message, error) {
	switch frame.MessageType {
	case sv2.MsgTypeSetupConnectionSuccess:
		return sv2.ParseSetupConnectionSuccess(frame.Payload)
	case sv2.MsgTypeSetupConnectionError:
		return sv2.ParseSetupConnectionError(frame.Payload)
	case sv2.MsgTypeOpenStandardMiningChannelSuccess:
		return sv2.ParseOpenStandardMiningChannelSuccess(frame.Payload)
	case sv2.MsgTypeOpenStandardMiningChannelError:
		return sv2.ParseOpenStandardMiningChannelError(frame.Payload)
	case sv2.MsgTypeNewMiningJob:
		return sv2.ParseNewMiningJob(frame.Payload)
	case sv2.MsgTypeSetNewPrevHash:
		return sv2.ParseSetNewPrevHash(frame.Payload)
	case sv2.MsgTypeSetTarget:
		return sv2.ParseSetTarget(frame.Payload)
	case sv2.MsgTypeSubmitSharesSuccess:
		return sv2.ParseSubmitSharesSuccess(frame.Payload)
	case sv2.MsgTypeSubmitSharesError:
		return sv2.ParseSubmitSharesError(frame.Payload)
	default:
		return nil, fmt.Errorf("unsupported message type: 0x%02x", frame.MessageType)
	}
}

func (m *Miner) handleMessage(msg sv2.Message) error {
	fmt.Printf("[%s] Received: %s\n", m.Name, sv2.GetMessageTypeName(msg.Type()))

	switch v := msg.(type) {
	case *sv2.SetupConnectionSuccess:
		return m.handleSetupConnectionSuccess(v)
	case *sv2.SetupConnectionError:
		return m.handleSetupConnectionError(v)
	case *sv2.OpenStandardMiningChannelSuccess:
		return m.handleOpenStandardMiningChannelSuccess(v)
	case *sv2.OpenStandardMiningChannelError:
		return m.handleOpenStandardMiningChannelError(v)
	case *sv2.NewMiningJob:
		return m.handleNewMiningJob(v)
	case *sv2.SetNewPrevHash:
		return m.handleSetNewPrevHash(v)
	case *sv2.SetTarget:
		return m.handleSetTarget(v)
	case *sv2.SubmitSharesSuccess:
		return m.handleSubmitSharesSuccess(v)
	case *sv2.SubmitSharesError:
		return m.handleSubmitSharesError(v)
	default:
		fmt.Printf("[%s] Unhandled message type: %T\n", m.Name, msg)
	}

	return nil
}

func (m *Miner) handleSetupConnectionSuccess(msg *sv2.SetupConnectionSuccess) error {
	fmt.Printf("[%s] SetupConnection successful\n", m.Name)
	m.State = StateConnectionSetup
	return m.openMiningChannel()
}

func (m *Miner) handleSetupConnectionError(msg *sv2.SetupConnectionError) error {
	return fmt.Errorf("setup connection error: %s", msg.ErrorCode)
}

func (m *Miner) handleOpenStandardMiningChannelSuccess(msg *sv2.OpenStandardMiningChannelSuccess) error {
	fmt.Printf("[%s] Mining channel opened: channel_id=%d\n", m.Name, msg.ChannelID)

	session := NewMiningSession()
	session.SetTarget(msg.Target)

	m.Channel = &MiningChannel{
		ChannelID: msg.ChannelID,
		Session:   session,
	}

	m.State = StateChannelOpen
	return nil
}

func (m *Miner) handleOpenStandardMiningChannelError(msg *sv2.OpenStandardMiningChannelError) error {
	return fmt.Errorf("open mining channel error: %s", msg.ErrorCode)
}

func (m *Miner) handleNewMiningJob(msg *sv2.NewMiningJob) error {
	if m.Channel == nil {
		return fmt.Errorf("no channel established")
	}

	if msg.ChannelID != m.Channel.ChannelID {
		return fmt.Errorf("channel ID mismatch")
	}

	job := &MiningJob{
		UID:        msg.JobID,
		Version:    msg.Version,
		MerkleRoot: msg.MerkleRoot,
		DiffTarget: m.Channel.Session.CurrTarget,
	}

	m.Channel.Session.AddJob(job)

	fmt.Printf("[%s] New mining job: job_id=%d, future=%v\n",
		m.Name, msg.JobID, msg.FutureJob)

	if !msg.FutureJob {
		m.startMining(job)
	}

	return nil
}

func (m *Miner) handleSetNewPrevHash(msg *sv2.SetNewPrevHash) error {
	if m.Channel == nil {
		return fmt.Errorf("no channel established")
	}

	if msg.ChannelID != m.Channel.ChannelID {
		return fmt.Errorf("channel ID mismatch")
	}

	job := m.Channel.Session.GetJob(msg.JobID)
	if job == nil {
		return fmt.Errorf("job not found: %d", msg.JobID)
	}

	m.Channel.Session.RetireAllJobs()
	m.Channel.Session.SetPrevHash(msg.PrevHash, msg.MinNTime, msg.NBits)

	fmt.Printf("[%s] SetNewPrevHash: job_id=%d\n", m.Name, msg.JobID)
	m.startMining(job)

	return nil
}

func (m *Miner) handleSetTarget(msg *sv2.SetTarget) error {
	if m.Channel == nil {
		return fmt.Errorf("no channel established")
	}

	if msg.ChannelID != m.Channel.ChannelID {
		return fmt.Errorf("channel ID mismatch")
	}

	m.Channel.Session.SetTarget(msg.MaxTarget)
	fmt.Printf("[%s] SetTarget updated\n", m.Name)

	return nil
}

func (m *Miner) handleSubmitSharesSuccess(msg *sv2.SubmitSharesSuccess) error {
	fmt.Printf("[%s] Share accepted! new_shares_sum=%d\n", m.Name, msg.NewSharesSum)
	return nil
}

func (m *Miner) handleSubmitSharesError(msg *sv2.SubmitSharesError) error {
	fmt.Printf("[%s] Share rejected: %s\n", m.Name, msg.ErrorCode)
	return nil
}

func (m *Miner) startMining(job *MiningJob) {
	if m.CurrentJob != nil {
		m.CurrentJob.Cancel()
		close(m.stopMining)
		m.miningWg.Wait()
		m.stopMining = make(chan struct{})
	}

	m.CurrentJob = job
	m.State = StateMining

	m.miningWg.Add(1)
	go m.mine(job)
}

func (m *Miner) mine(job *MiningJob) {
	defer m.miningWg.Done()

	job.StartedAt = time.Now()

	session := m.Channel.Session
	session.mu.RLock()
	prevHash := session.PrevHash
	minNTime := session.MinNTime
	nbits := session.NBits
	target := session.CurrTarget
	session.mu.RUnlock()

	if prevHash == nil {
		fmt.Printf("[%s] Cannot mine: no prev hash\n", m.Name)
		return
	}

	header := m.assembleHeader(job.Version, prevHash, job.MerkleRoot, minNTime, nbits)

	fmt.Printf("[%s] Mining job %d\n", m.Name, job.UID)

	var nonce uint32
	minHash := make([]byte, 32)
	for i := range minHash {
		minHash[i] = 0xFF
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastReport := time.Now()
	hashCount := uint64(0)

	for {
		select {
		case <-m.stopMining:
			fmt.Printf("[%s] Mining stopped for job %d\n", m.Name, job.UID)
			return
		case <-ticker.C:
			if time.Since(lastReport) >= 5*time.Second {
				elapsed := time.Since(job.StartedAt).Seconds()
				hashrate := float64(hashCount) / elapsed / 1e9
				fmt.Printf("[%s] Hashrate: %.6f GH/s, nonce: %d\n", m.Name, hashrate, nonce)
				lastReport = time.Now()
			}
		default:
		}

		if job.Cancelled() {
			return
		}

		fullHeader := append(header, intToLittleEndian(nonce, 4)...)
		hash := doubleHashBitcoin(fullHeader)

		if bytes.Compare(hash, minHash) < 0 {
			minHash = hash
		}

		if bytes.Compare(hash, target) < 0 {
			fmt.Printf("[%s] Solution found! job_id=%d, nonce=%d\n", m.Name, job.UID, nonce)
			m.submitShare(job, nonce, minNTime, job.Version)
		}

		nonce++
		hashCount++

		if nonce%10000 == 0 {
			time.Sleep(time.Microsecond)
		}
	}
}

func (m *Miner) assembleHeader(version uint32, prevHash, merkleRoot []byte, ntime, nbits uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, version)
	buf.Write(prevHash)
	buf.Write(merkleRoot)
	binary.Write(buf, binary.LittleEndian, ntime)
	binary.Write(buf, binary.LittleEndian, nbits)

	return buf.Bytes()
}

func (m *Miner) submitShare(job *MiningJob, nonce, ntime, version uint32) error {
	msg := sv2.SubmitSharesStandard{
		ChannelID:      m.Channel.ChannelID,
		SequenceNumber: 0,
		JobID:          job.UID,
		Nonce:          nonce,
		NTime:          ntime,
		Version:        version,
	}

	return m.Conn.SendMessage(&msg)
}

func intToLittleEndian(num uint32, byteno int) []byte {
	buf := make([]byte, byteno)
	binary.LittleEndian.PutUint32(buf, num)
	return buf
}

func doubleHashBitcoin(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

func (m *Miner) Close() {
	if m.CurrentJob != nil {
		m.CurrentJob.Cancel()
		close(m.stopMining)
		m.miningWg.Wait()
	}
	if m.Conn != nil {
		m.Conn.Close()
	}
}

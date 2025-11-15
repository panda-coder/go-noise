package sv2

import (
	"bytes"
	"testing"
)

func TestU8(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  []byte
	}{
		{"zero", 0, []byte{0}},
		{"max", 255, []byte{255}},
		{"arbitrary", 42, []byte{42}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := U8(tt.value)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("U8(%d) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestU16(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  []byte
	}{
		{"zero", 0, []byte{0, 0}},
		{"max", 65535, []byte{255, 255}},
		{"arbitrary", 258, []byte{2, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := U16(tt.value)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("U16(%d) = %v, want %v", tt.value, got, tt.want)
			}

			val, err := ReadU16(got)
			if err != nil {
				t.Errorf("ReadU16() error = %v", err)
			}
			if val != tt.value {
				t.Errorf("ReadU16(%v) = %d, want %d", got, val, tt.value)
			}
		})
	}
}

func TestU32(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		want  []byte
	}{
		{"zero", 0, []byte{0, 0, 0, 0}},
		{"max", 4294967295, []byte{255, 255, 255, 255}},
		{"arbitrary", 0x12345678, []byte{0x78, 0x56, 0x34, 0x12}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := U32(tt.value)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("U32(%d) = %v, want %v", tt.value, got, tt.want)
			}

			val, err := ReadU32(got)
			if err != nil {
				t.Errorf("ReadU32() error = %v", err)
			}
			if val != tt.value {
				t.Errorf("ReadU32(%v) = %d, want %d", got, val, tt.value)
			}
		})
	}
}

func TestU256(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{
			name:  "valid 32 bytes",
			value: make([]byte, 32),
		},
		{
			name:    "too short",
			value:   make([]byte, 31),
			wantErr: true,
		},
		{
			name:    "too long",
			value:   make([]byte, 33),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := U256(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("U256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if !bytes.Equal(got, tt.value) {
					t.Errorf("U256() = %v, want %v", got, tt.value)
				}

				val, err := ReadU256(got)
				if err != nil {
					t.Errorf("ReadU256() error = %v", err)
				}
				if !bytes.Equal(val, tt.value) {
					t.Errorf("ReadU256() = %v, want %v", val, tt.value)
				}
			}
		})
	}
}

func TestSTR0_255(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"empty", "", false},
		{"short", "test", false},
		{"max length", string(make([]byte, 255)), false},
		{"too long", string(make([]byte, 256)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := STR0_255(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("STR0_255() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) < 1 {
					t.Errorf("STR0_255() result too short")
					return
				}
				if got[0] != uint8(len(tt.value)) {
					t.Errorf("STR0_255() length prefix = %d, want %d", got[0], len(tt.value))
				}
				if string(got[1:]) != tt.value {
					t.Errorf("STR0_255() content = %s, want %s", string(got[1:]), tt.value)
				}

				val, n, err := ReadSTR0_255(got)
				if err != nil {
					t.Errorf("ReadSTR0_255() error = %v", err)
				}
				if val != tt.value {
					t.Errorf("ReadSTR0_255() = %s, want %s", val, tt.value)
				}
				if n != len(got) {
					t.Errorf("ReadSTR0_255() bytes read = %d, want %d", n, len(got))
				}
			}
		})
	}
}

func TestB0_32(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{"empty", []byte{}, false},
		{"short", []byte{1, 2, 3}, false},
		{"max length", make([]byte, 32), false},
		{"too long", make([]byte, 33), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := B0_32(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("B0_32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) < 1 {
					t.Errorf("B0_32() result too short")
					return
				}
				if got[0] != uint8(len(tt.value)) {
					t.Errorf("B0_32() length prefix = %d, want %d", got[0], len(tt.value))
				}
				if !bytes.Equal(got[1:], tt.value) {
					t.Errorf("B0_32() content = %v, want %v", got[1:], tt.value)
				}

				val, n, err := ReadB0_32(got)
				if err != nil {
					t.Errorf("ReadB0_32() error = %v", err)
				}
				if !bytes.Equal(val, tt.value) {
					t.Errorf("ReadB0_32() = %v, want %v", val, tt.value)
				}
				if n != len(got) {
					t.Errorf("ReadB0_32() bytes read = %d, want %d", n, len(got))
				}
			}
		})
	}
}

func TestBOOL(t *testing.T) {
	tests := []struct {
		name  string
		value bool
		want  []byte
	}{
		{"true", true, []byte{1}},
		{"false", false, []byte{0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BOOL(tt.value)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("BOOL(%v) = %v, want %v", tt.value, got, tt.want)
			}

			val, err := ReadBOOL(got)
			if err != nil {
				t.Errorf("ReadBOOL() error = %v", err)
			}
			if val != tt.value {
				t.Errorf("ReadBOOL(%v) = %v, want %v", got, val, tt.value)
			}
		})
	}
}

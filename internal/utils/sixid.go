package utils

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"strings"
)

// SixIDHookFunc defines the signature for the NewSixID test hook.
// It returns a SixID and a boolean indicating whether to override the default generation.
type SixIDHookFunc func() (id SixID, override bool)

// NewSixIDHook is a package-level variable that tests can set to override NewSixID behavior.
var NewSixIDHook SixIDHookFunc

// SixID is a 6-byte ID stored as BSON BinData with custom subtype 0x80
type SixID [6]byte

// NewSixID creates a new 6-byte SixID using random data
func NewSixID() SixID {
	if NewSixIDHook != nil {
		if id, override := NewSixIDHook(); override {
			return id
		}
	}

	var id SixID
	_, err := rand.Read(id[:])
	if err != nil {
		// fallback to zeros if random fails
		for i := range id {
			id[i] = 0
		}
	}
	return id
}

// ParseSixID parses a string into a SixID from its Crockford Base32 string representation.
func ParseSixID(s string) (SixID, error) {
	return ParseCrockfordSixID(s)
}

// Crockford Base32 encoding alphabet (uppercase)
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Mapping from Crockford Base32 chars to their values
var crockfordDecodeMap map[byte]byte

func init() {
	// Initialize the decoding map
	crockfordDecodeMap = make(map[byte]byte, 32)
	for i := range crockfordAlphabet {
		crockfordDecodeMap[crockfordAlphabet[i]] = byte(i)
	}

	// Add lowercase variants
	lower := strings.ToLower(crockfordAlphabet)
	for i := range lower {
		if i >= 10 { // Skip numbers
			crockfordDecodeMap[lower[i]] = byte(i)
		}
	}

	// Add commonly confused characters
	crockfordDecodeMap['o'] = crockfordDecodeMap['O'] // o->O
	crockfordDecodeMap['i'] = crockfordDecodeMap['1'] // i->1
	crockfordDecodeMap['l'] = crockfordDecodeMap['1'] // l->1
}

// String returns the Crockford Base32 (uppercase) representation of the 6-byte SixID
func (u SixID) String() string {
	if len(u) != 6 {
		return ""
	}

	var bytes = u[:]

	// 6 bytes = 48 bits, requires ceil(48/5) = 10 characters in Base32
	result := make([]byte, 10)
	var bits, offset uint
	resultIndex := 0

	for i := 0; i < 6; i++ {
		bits |= uint(bytes[i]) << offset
		offset += 8

		for offset >= 5 {
			result[resultIndex] = crockfordAlphabet[bits&0x1F]
			resultIndex++
			bits >>= 5
			offset -= 5
		}
	}

	if offset > 0 {
		result[resultIndex] = crockfordAlphabet[bits&0x1F]
		resultIndex++
	}

	return string(result[:resultIndex])
}

// ParseCrockfordSixID converts a Crockford Base32 string back to 6-byte SixID
func ParseCrockfordSixID(s string) (SixID, error) {
	if s == "" {
		return SixID{}, nil
	}

	// Remove hyphens and spaces for leniency
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")

	// Must be exactly 10 characters for 6 bytes (48 bits)
	if len(s) != 10 {
		return SixID{}, errors.New("invalid Crockford Base32 SixID: string length must be 10")
	}

	var bits uint64
	var offset uint
	bytes := make([]byte, 6)
	byteIndex := 0

	for i := 0; i < 10; i++ {
		val, ok := crockfordDecodeMap[s[i]]
		if !ok {
			return SixID{}, errors.New("invalid character in Crockford Base32 SixID")
		}

		bits |= uint64(val) << offset
		offset += 5

		for offset >= 8 && byteIndex < 6 {
			bytes[byteIndex] = byte(bits & 0xFF)
			byteIndex++
			bits >>= 8
			offset -= 8
		}
	}

	if byteIndex != 6 {
		return SixID{}, errors.New("invalid Crockford Base32 SixID: couldn't decode 6 bytes")
	}

	var id SixID
	copy(id[:], bytes)
	return id, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (u SixID) MarshalBinary() ([]byte, error) {
	return u[:], nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (u *SixID) UnmarshalBinary(data []byte) error {
	if len(data) != 6 {
		return errors.New("invalid SixID length")
	}
	copy((*u)[:], data)
	return nil
}

// GetBSON returns a MongoDB-compatible representation of the SixID with custom subtype 0x80
func (u SixID) GetBSON() (interface{}, error) {
	return primitive.Binary{
		Subtype: 0x80, // custom subtype
		Data:    u[:],
	}, nil
}

// MarshalJSON marshals the SixID as a JSON string in Crockford Base32 format.
func (u SixID) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON unmarshals a SixID from a JSON string in Crockford Base32 format.
func (u *SixID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseSixID(s)
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

// SetBSON implements the bson.Setter interface
func (u *SixID) SetBSON(raw interface{}) error {
	// Handle nil or empty data
	if raw == nil {
		// If BSON value is null, treat as zero SixID for the value type.
		// For pointer *SixID fields, this SetBSON on the value type might not even be called if the pointer itself is nil.
		*u = SixID{}
		return nil
	}

	// Try to convert from binary with subtype 0x80 and length 6
	switch v := raw.(type) {
	case primitive.Binary:
		if v.Subtype == 0x80 && len(v.Data) == 6 {
			copy((*u)[:], v.Data)
			return nil
		} else {
			// Invalid subtype or length
			*u = SixID{} // Set to zero on error
			return errors.New("invalid BSON binary data for SixID: incorrect subtype or length")
		}
	default:
		// Not a primitive.Binary type
		*u = SixID{} // Set to zero on error
		return errors.New("invalid BSON type for SixID: expected primitive.Binary")
	}
}

package analyzer

import (
	"encoding/binary"
	"encoding/json"
)

// ProtocolPattern represents a detected pattern in the protocol
type ProtocolPattern struct {
	Offset      int    `json:"offset"`
	Length      int    `json:"length"`
	PatternType string `json:"pattern_type"`
	Value       string `json:"value"`
}

// ProtocolAnalyzer handles protocol analysis and pattern detection
type ProtocolAnalyzer struct {
	patterns []ProtocolPattern
}

// NewProtocolAnalyzer creates a new protocol analyzer
func NewProtocolAnalyzer() *ProtocolAnalyzer {
	return &ProtocolAnalyzer{
		patterns: make([]ProtocolPattern, 0),
	}
}

// AnalyzePayload examines the payload for common patterns
func (pa *ProtocolAnalyzer) AnalyzePayload(payload []byte) []ProtocolPattern {
	patterns := make([]ProtocolPattern, 0)

	// Look for common protocol patterns
	patterns = append(patterns, pa.detectHeaders(payload)...)
	patterns = append(patterns, pa.detectLengthFields(payload)...)
	patterns = append(patterns, pa.detectDelimiters(payload)...)

	return patterns
}

func (pa *ProtocolAnalyzer) detectHeaders(payload []byte) []ProtocolPattern {
	patterns := make([]ProtocolPattern, 0)

	// Example: Look for magic bytes at the start of payload
	if len(payload) >= 4 {
		pattern := ProtocolPattern{
			Offset:      0,
			Length:      4,
			PatternType: "header",
			Value:       string(payload[:4]),
		}
		patterns = append(patterns, pattern)
	}

	return patterns
}

func (pa *ProtocolAnalyzer) detectLengthFields(payload []byte) []ProtocolPattern {
	patterns := make([]ProtocolPattern, 0)

	// Example: Look for length fields (assuming 2-byte length field)
	if len(payload) >= 6 {
		length := binary.BigEndian.Uint16(payload[4:6])
		if int(length) == len(payload)-6 {
			pattern := ProtocolPattern{
				Offset:      4,
				Length:      2,
				PatternType: "length_field",
				Value:       string(payload[4:6]),
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

func (pa *ProtocolAnalyzer) detectDelimiters(payload []byte) []ProtocolPattern {
	patterns := make([]ProtocolPattern, 0)

	// Example: Look for common delimiters
	delimiters := []byte{',', '|', '\n', '\r'}
	for i, b := range payload {
		for _, delimiter := range delimiters {
			if b == delimiter {
				pattern := ProtocolPattern{
					Offset:      i,
					Length:      1,
					PatternType: "delimiter",
					Value:       string([]byte{delimiter}),
				}
				patterns = append(patterns, pattern)
			}
		}
	}

	return patterns
}

// ExportPatterns exports the detected patterns to JSON
func (pa *ProtocolAnalyzer) ExportPatterns() ([]byte, error) {
	return json.MarshalIndent(pa.patterns, "", "  ")
}

package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestConformance(t *testing.T) {
	data, err := os.ReadFile("../../../protocol/testdata/envelopes.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name  string
		Valid bool
		Wire  string
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := Decode([]byte(tc.Wire))
			if (err == nil) != tc.Valid {
				t.Fatalf("accepted=%v want=%v", err == nil, tc.Valid)
			}
		})
	}
}

func TestBounds(t *testing.T) {
	for _, data := range [][]byte{
		bytes.Repeat([]byte(" "), MaxFrame+1),
		[]byte("{\"v\":1,\"type\":\"ok\",\"body\":{\"x\":\"\xff\"}}"),
		[]byte(`{"v":1,"type":"ok","body":{"x":[[[[[[[[0]]]]]]]]}}`),
	} {
		if _, err := Decode(data); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}

func TestStrictBodies(t *testing.T) {
	var proof AuthProof
	if Strict([]byte(`{"uuid":"x","signature":"!"}`), &proof) == nil {
		t.Fatal("invalid base64 accepted")
	}
	if Strict([]byte(`{"uuid":"x","signature":"","public_key":""}`), &proof) == nil {
		t.Fatal("unknown field accepted")
	}
	if Strict([]byte(`{"UUID":"x","signature":""}`), &proof) == nil {
		t.Fatal("field alias accepted")
	}
	if Strict([]byte(`{"uuid":null,"signature":""}`), &proof) == nil {
		t.Fatal("null accepted")
	}
}

func TestTranscriptBoundaries(t *testing.T) {
	a := Transcript([]byte("ab"), []byte("c"))
	b := Transcript([]byte("a"), []byte("bc"))
	if bytes.Equal(a, b) {
		t.Fatal("ambiguous transcript")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"v":1,"type":"room.leave","body":{}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := Decode(data)
		if err != nil {
			return
		}
		out, err := Encode(e.Type, e.RequestID, e.Body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Decode(out); err != nil {
			t.Fatal(err)
		}
	})
}

func BenchmarkDecode(b *testing.B) {
	data := []byte(`{"v":1,"type":"message.send","request_id":"1","body":{"room_id":"K7P9X2M4QA","revision":1,"epoch":1,"ciphertext":"AQIDBA=="}}`)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

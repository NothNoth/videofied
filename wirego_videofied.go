package main

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/quarkslab/wirego/wirego_remote/go/wirego"
)

// Define here enum identifiers, used to refer to a specific field
const (
	FieldIdentRequest_Unk      wirego.FieldId = 1
	FieldIdentResponse_Serial  wirego.FieldId = 2
	FieldIdentResponse_Unk     wirego.FieldId = 3
	FieldSetKey_Key            wirego.FieldId = 4
	FieldVersion_High          wirego.FieldId = 5
	FieldVersion_Low           wirego.FieldId = 6
	FieldAuth1_ServerChallenge wirego.FieldId = 7

	FieldAuth2_EncryptedServerChallenge wirego.FieldId = 8
	FieldAuth2_ClientChallenge          wirego.FieldId = 9

	FieldAuth3_EncryptedClientChallenge wirego.FieldId = 10

	FieldAuthSuccess_Unknown1  wirego.FieldId = 11
	FieldAuthSuccess_Unknown2  wirego.FieldId = 12
	FieldAuthSuccess_Unknown3  wirego.FieldId = 13
	FieldAuthSuccess_Unknown4  wirego.FieldId = 14
	FieldAuthSuccess_Unknown5  wirego.FieldId = 15
	FieldAuthSuccess_Unknown6  wirego.FieldId = 16
	FieldAuthSuccess_Unknown7  wirego.FieldId = 17
	FieldAuthSuccess_Unknown8  wirego.FieldId = 18
	FieldAuthSuccess_Unknown9  wirego.FieldId = 19
	FieldAuthSuccess_Unknown10 wirego.FieldId = 20

	FieldEvent_Number  wirego.FieldId = 21
	FieldEvent_Source  wirego.FieldId = 22
	FieldEvent_Unknown wirego.FieldId = 23

	FieldReqAck_Unknown wirego.FieldId = 24
)

// Since we implement the wirego.WiregoInterface we need some structure to hold it.
type Videofied struct {
	AESKey string
}

func main() {
	var wge Videofied

	wg, err := wirego.New("ipc:///tmp/wirego0", false, wge)
	if err != nil {
		fmt.Println(err)
		return
	}
	wg.ResultsCacheEnable(false)

	wg.Listen()
}

// This function shall return the plugin name
func (Videofied) GetName() string {
	return "Videofied alarm"
}

// This function shall return the wireshark filter
func (Videofied) GetFilter() string {
	return "videofied"
}

// GetFields returns the list of fields descriptor that we may eventually return
// when dissecting a packet payload
func (Videofied) GetFields() []wirego.WiresharkField {
	var fields []wirego.WiresharkField

	//Setup our wireshark custom fields
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdentRequest_Unk, Name: "Ident Req Unk", Filter: "videofied.ident_req_unk", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdentResponse_Serial, Name: "Serial", Filter: "videofied.serial", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldIdentResponse_Unk, Name: "Ident Resp Unk", Filter: "videofied.ident_resp_unk", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldSetKey_Key, Name: "Key", Filter: "videofied.key", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldVersion_High, Name: "Version High", Filter: "videofied.version_high", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldVersion_Low, Name: "Version Low", Filter: "videofied.version_low", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuth1_ServerChallenge, Name: "Server Challenge", Filter: "videofied.srv_challenge", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuth2_EncryptedServerChallenge, Name: "Encrypted Server Challenge", Filter: "videofied.encrypted_srv_challenge", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuth2_ClientChallenge, Name: "Client Challenge", Filter: "videofied.client_challenge", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuth3_EncryptedClientChallenge, Name: "Encrypted Client Challenge", Filter: "videofied.encrypted_cli_challenge", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown1, Name: "Unknown 1", Filter: "videofied.auth_success_unk1", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown2, Name: "Unknown 2", Filter: "videofied.auth_success_unk2", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown3, Name: "Unknown 3", Filter: "videofied.auth_success_unk3", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown4, Name: "Unknown 4", Filter: "videofied.auth_success_unk4", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown5, Name: "Unknown 5", Filter: "videofied.auth_success_unk5", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown6, Name: "Unknown 6", Filter: "videofied.auth_success_unk6", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown7, Name: "Unknown 7", Filter: "videofied.auth_success_unk7", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown8, Name: "Unknown 8", Filter: "videofied.auth_success_unk8", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown9, Name: "Unknown 9", Filter: "videofied.auth_success_unk9", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldAuthSuccess_Unknown10, Name: "Unknown 10", Filter: "videofied.auth_success_unk10", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})

	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldEvent_Number, Name: "Event number", Filter: "videofied.event_number", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldEvent_Source, Name: "Event source", Filter: "videofied.event_source", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldEvent_Unknown, Name: "Unknown", Filter: "videofied.event_unk", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	fields = append(fields, wirego.WiresharkField{WiregoFieldId: FieldReqAck_Unknown, Name: "Unknown", Filter: "videofied.reqack_unk", ValueType: wirego.ValueTypeString, DisplayMode: wirego.DisplayModeNone})
	return fields
}

// GetDetectionFilters returns a wireshark filter that will select which packets
// will be sent to your dissector for parsing.
// Two types of filters can be defined: Integers or Strings
func (Videofied) GetDetectionFilters() []wirego.DetectionFilter {
	var filters []wirego.DetectionFilter

	filters = append(filters, wirego.DetectionFilter{FilterType: wirego.DetectionFilterTypeInt, Name: "tcp.port", ValueInt: 888})

	return filters
}

// GetDetectionHeuristicsParents returns a list of protocols on top of which detection heuristic
// should be called.
func (Videofied) GetDetectionHeuristicsParents() []string {
	//We want to apply our detection heuristic on all tcp payloads
	return []string{}
}

// DetectionHeuristic applies an heuristic to identify the protocol.
func (Videofied) DetectionHeuristic(packetNumber int, src string, dst string, layer string, packet []byte) bool {
	return false
}

var AESKey []byte
var ServerChallenge []byte
var ClientChallenge []byte

// DissectPacket provides the packet payload to be parsed.
func (vf Videofied) DissectPacket(packetNumber int, src string, dst string, layer string, packet []byte) *wirego.DissectResult {
	var res wirego.DissectResult

	res.Protocol = "Videofied"

	chunks := bytes.Split(packet, []byte{0x1A})

	str := string(chunks[0])
	if len(str) == 0 {
		res.Info = "Unknown packet"
		return &res
	}

	split := strings.Split(str, ",")

	switch split[0] {

	case "IDENT":
		if len(split) == 2 {
			res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdentRequest_Unk, Offset: strings.Index(str, split[1]), Length: len(split[1])})
			res.Info = "Server> Ident request"
		} else {
			res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdentResponse_Serial, Offset: strings.Index(str, split[1]), Length: len(split[1])})
			res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldIdentResponse_Unk, Offset: strings.LastIndex(str, ",") + 1, Length: len(split[2])})
			res.Info = "Client> Ident response (Serial: " + split[1] + ")"
		}

	case "SETKEY":
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldSetKey_Key, Offset: strings.Index(str, split[1]), Length: len(split[1])})
		res.Info = "Server> Set key packet (Key: " + split[1] + ")"
		AESKey, _ = hex.DecodeString(split[1])

	case "VERSION":
		res.Info = "Server> Version/Server challenge packet"
		//Chunk 1 is version
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldVersion_High, Offset: strings.Index(str, split[1]), Length: len(split[1])})
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldVersion_High, Offset: strings.Index(str, split[2]), Length: len(split[2])})
		if len(chunks) == 2 && len(chunks[1]) != 0 {
			//Chunk 2 is challenge
			split2 := strings.Split(string(chunks[1]), ",")
			res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuth1_ServerChallenge, Offset: strings.Index(string(packet), split2[1]), Length: len(split2[1])})
			ServerChallenge, _ = hex.DecodeString(split2[1])
		}
	case "AUTH1":
		res.Info = "Server> Server challenge packet"
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuth1_ServerChallenge, Offset: strings.Index(string(packet), split[1]), Length: len(split[1])})
		ServerChallenge, _ = hex.DecodeString(split[1])

	case "AUTH2":
		res.Info = "Client> Client challenge response / Client challenge"
		if len(AESKey) == 0 {
			res.Info += " (Aes key is missing)"
			break
		}
		cip, _ := aes.NewCipher(AESKey)
		out := make([]byte, cip.BlockSize())
		cip.Encrypt(out, ServerChallenge)
		h := strings.ToUpper(hex.EncodeToString(out))
		if h == split[1] {
			res.Info += " (encrypted server challenge is valid)"
		} else {
			res.Info += " (encrypted server challenge is invalid)"
			fmt.Println(h)
		}
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuth2_EncryptedServerChallenge, Offset: strings.Index(str, split[1]), Length: len(split[1])})
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuth2_ClientChallenge, Offset: strings.Index(str, split[2]), Length: len(split[2])})
		ClientChallenge, _ = hex.DecodeString(split[2])

	case "AUTH3":
		res.Info = "Server> Server challenge response"
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuth3_EncryptedClientChallenge, Offset: strings.Index(str, split[1]), Length: len(split[1])})
		if len(AESKey) == 0 {
			res.Info += " (Aes key is missing)"
			break
		}
		cip, _ := aes.NewCipher(AESKey)
		out := make([]byte, cip.BlockSize())
		cip.Encrypt(out, ClientChallenge)
		h := strings.ToUpper(hex.EncodeToString(out))
		if h == split[1] {
			res.Info += " (encrypted client challenge is valid)"
		} else {
			res.Info += " (encrypted client challenge is invalid)"
			fmt.Println(h)
		}

	case "AUTH_SUCCESS":
		res.Info = "Client> Auth success packet"

		offs := len(split[0]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown1, Offset: offs, Length: len(split[1])})
		offs += len(split[1]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown2, Offset: offs, Length: len(split[2])})
		offs += len(split[2]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown3, Offset: offs, Length: len(split[3])})
		offs += len(split[3]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown4, Offset: offs, Length: len(split[4])})
		offs += len(split[4]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown5, Offset: offs, Length: len(split[5])})
		offs += len(split[5]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown6, Offset: offs, Length: len(split[6])})
		offs += len(split[6]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown7, Offset: offs, Length: len(split[7])})
		offs += len(split[7]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown8, Offset: offs, Length: len(split[8])})
		offs += len(split[8]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown9, Offset: offs, Length: len(split[9])})
		offs += len(split[9]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldAuthSuccess_Unknown10, Offset: offs, Length: len(split[10])})

	case "EVENT":
		res.Info = "Client> Event packet"
		offs := len(split[0]) + 1
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldEvent_Number, Offset: offs, Length: len(split[1])})
		offs += len(split[1]) + 1
		if len(split) >= 3 {
			res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldEvent_Source, Offset: offs, Length: len(split[2])})
			offs += len(split[2]) + 1
			if len(split) >= 4 {
				res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldEvent_Unknown, Offset: offs, Length: len(split[3])})
			}

		}

	case "REQACK":
		res.Info = "Client> Request ack packet"
		res.Fields = append(res.Fields, wirego.DissectField{WiregoFieldId: FieldReqAck_Unknown, Offset: strings.Index(str, split[1]), Length: len(split[1])})

	case "ACK":
		res.Info = "Server> Ack packet"

	}

	return &res
}

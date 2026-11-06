//go:build darwin && cgo

package policy

import (
	"net"
	"testing"
)

// Reserve the same port for both protocols so protocol filtering, rather than
// an absent listener, determines the outcome. UDP probes exchange real data.
func seatbeltIPListeners(t *testing.T) (string, uint16) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	addr := tcp.Addr().String()
	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		var b [64]byte
		for {
			n, peer, err := udp.ReadFrom(b[:])
			if err != nil {
				return
			}
			udp.WriteTo(b[:n], peer)
		}
	}()
	return addr, uint16(tcp.Addr().(*net.TCPAddr).Port)
}

func TestSeatbeltEnforceIPConnect(t *testing.T) {
	allowed, port := seatbeltIPListeners(t)
	other, _ := seatbeltIPListeners(t)
	for _, tc := range []struct {
		name            string
		net             NetConfig
		tcp, udp, other bool
	}{
		{"deny", NetConfig{}, false, false, false},
		{"allow", NetConfig{Allow: true}, true, true, true},
		{"default-tcp", NetConfig{Rules: []NetRule{{Port: port, Access: "connect"}}}, true, false, false},
		{"tcp", NetConfig{Rules: []NetRule{{Port: port, Access: "connect", Proto: "tcp"}}}, true, false, false},
		{"udp", NetConfig{Rules: []NetRule{{Port: port, Access: "connect", Proto: "udp"}}}, false, true, false},
		{"both", NetConfig{Rules: []NetRule{{Port: port, Access: "connect", Proto: "any"}}}, true, true, false},
		{"bind-only", NetConfig{Rules: []NetRule{{Port: port, Access: "bind", Proto: "any"}}}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seatbeltRun(t, seatbeltCompile(t, &Policy{Net: tc.net}, []seatbeltProbe{
				{"tcp-connect", allowed, !tc.tcp},
				{"udp-connect", allowed, !tc.udp},
				{"tcp-connect", other, !tc.other},
				{"udp-connect", other, !tc.other},
			}))
		})
	}
}

func TestSeatbeltEnforceIPBind(t *testing.T) {
	// Obtain two unused ports. Close the reservations before the sandboxed
	// process binds them; EADDRINUSE is a failure, never a successful denial.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	otherReservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer otherReservation.Close()
	allowed := reservation.Addr().String()
	other := otherReservation.Addr().String()
	port := uint16(reservation.Addr().(*net.TCPAddr).Port)
	reservation.Close()
	otherReservation.Close()
	for _, tc := range []struct {
		name            string
		net             NetConfig
		tcp, udp, other bool
	}{
		{"deny", NetConfig{}, false, false, false},
		{"allow", NetConfig{Allow: true}, true, true, true},
		{"tcp", NetConfig{Rules: []NetRule{{Port: port, Access: "bind", Proto: "tcp"}}}, true, false, false},
		{"udp", NetConfig{Rules: []NetRule{{Port: port, Access: "bind", Proto: "udp"}}}, false, true, false},
		{"both", NetConfig{Rules: []NetRule{{Port: port, Access: "bind", Proto: "any"}}}, true, true, false},
		{"connect-only", NetConfig{Rules: []NetRule{{Port: port, Access: "connect", Proto: "any"}}}, false, false, false},
		{"port-zero", NetConfig{Rules: []NetRule{{Access: "bind", Proto: "any"}}}, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seatbeltRun(t, seatbeltCompile(t, &Policy{Net: tc.net}, []seatbeltProbe{
				{"tcp-bind", allowed, !tc.tcp},
				{"udp-bind", allowed, !tc.udp},
				{"tcp-bind", other, !tc.other},
				{"udp-bind", other, !tc.other},
			}))
		})
	}
}

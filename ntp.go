package main

import (
	"encoding/binary"
	"net"
	"time"
)

// getNTPTime gets the current time from an NTP server
func getNTPTime() time.Time {
	type ntp struct {
		FirstByte, A, B, C uint8
		D, E, F            uint32
		G, H               uint64
		ReceiveTime        uint64
		J                  uint64
	}
	sock, err := net.Dial("udp", "us.pool.ntp.org:123")
	if err != nil {
		return time.Now()
	}
	defer sock.Close()
	sock.SetDeadline(time.Now().Add((2 * time.Second)))
	defer sock.SetDeadline(time.Time{})

	ntpTransmit := new(ntp)
	ntpTransmit.FirstByte = 0x1b

	binary.Write(sock, binary.BigEndian, ntpTransmit)
	binary.Read(sock, binary.BigEndian, ntpTransmit)

	var sec, frac uint64
	sec = uint64(ntpTransmit.ReceiveTime >> 32)
	frac = uint64(ntpTransmit.ReceiveTime & 0xffffffff)

	nsec := sec * 1e9
	nsec += (frac * 1e9) >> 32

	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(nsec))
}

// getExternalIP attempts to get the external IP address
func getExternalIP() string {
	// Try to connect to a public DNS server to get local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
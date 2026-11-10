package main

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// egressTimeout bounds the connect attempt: a blocked destination should
// fail fast (connection refused or no route), but a silently dropped
// packet would otherwise hang until the OS default TCP timeout, which is
// far longer than any case's own timeout budget.
const egressTimeout = 3 * time.Second

// runEgress connects to ip:port and sends a random nonce, so the host
// listener on the other end can match this specific attempt in its own
// log rather than just counting a connection.
func runEgress(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("rfprobe: egress: want <ip> <port>")
	}
	addr := net.JoinHostPort(args[0], args[1])

	conn, err := net.DialTimeout("tcp", addr, egressTimeout)
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()

	nonce := randomNonce()
	_ = conn.SetWriteDeadline(time.Now().Add(egressTimeout))
	if _, err := conn.Write([]byte(nonce)); err != nil {
		return fmt.Errorf("connected to %s but could not send nonce: %w", addr, err)
	}

	fmt.Printf("connected to %s, sent nonce %s\n", addr, nonce)
	return nil
}

func randomNonce() string {
	var b [8]byte
	if _, err := unix.Getrandom(b[:], 0); err != nil {
		// getrandom() failing is itself interesting but should not stop
		// the probe from reporting that the connection succeeded.
		return "no-random-available"
	}
	return fmt.Sprintf("%x", b)
}

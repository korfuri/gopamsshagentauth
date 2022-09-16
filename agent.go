package gopamsshagentauth

import (
	"golang.org/x/crypto/ssh/agent"

	"errors"
	"net"
	"os"
)

// Returns an Agent bound to the socket found in SSH_AUTH_SOCK, and a
// function to close that socket. Closing that socket invalidates the
// Agent.
//
// SECURITY RISK:
//   When using this in PAM mode, it's necessary to seteuid to the uid
//   of the target user before calling this function. This prevents
//   malicious Mallory from calling this PAM module with SSH_AUTH_SOCK
//   pointing to Alice's agent socket.
func GetAgentFromEnv() (agent.Agent, func(), error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if len(socket) == 0 {
		return nil, nil, errors.New("SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, err
	}
	agentClient := agent.NewClient(conn)
	return agentClient, func() { conn.Close() }, nil
}

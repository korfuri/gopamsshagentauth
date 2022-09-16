package gopamsshagentauth

import (
	// "crypto/rand"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"os"
	"reflect"
)

func GetAgentOrDie() agent.Agent {
	socket := os.Getenv("SSH_AUTH_SOCK")
	// TODO permission checks on socket
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agentClient := agent.NewClient(conn)
	return agentClient
}

type AuthorizedKey struct {
	Key           ssh.PublicKey
	CertAuthority bool
	Principals    []string
}

type AgentAuth struct {
	Agent          agent.Agent
	AuthorizedKeys []AuthorizedKey
}

type FakeConn struct {
	user string
}

func (c *FakeConn) User() string          { return c.user }
func (c *FakeConn) SessionID() []byte     { return []byte{} }
func (c *FakeConn) ClientVersion() []byte { return []byte{} }
func (c *FakeConn) ServerVersion() []byte { return []byte{} }
func (c *FakeConn) RemoteAddr() net.Addr {
	return c.LocalAddr()
}
func (c *FakeConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")
	return addr
}

// attemptCandidate returns true if a given agent key is a valid candidate
func (a AgentAuth) attemptCandidate(k *agent.Key) bool {
	// Unmarshaling and re-marshaling the agent key lets us use it
	// as a Certificate if it's of a certificate type.
	parsedKey, err := ssh.ParsePublicKey(k.Marshal())
	if err != nil {
		log.Printf("Can't unmarshal agent key %.40v, (err: %v) skipping", k, err)
		return false
	}

	for _, sk := range a.AuthorizedKeys {
		//log.Printf("attempting agent key %v against server key %v", parsedKey, sk)
		checker := ssh.CertChecker{
			IsUserAuthority: func(k ssh.PublicKey) bool {
				return bytes.Equal(k.Marshal(), sk.Key.Marshal())
			},
			UserKeyFallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
				if bytes.Equal(k.Marshal(), sk.Key.Marshal()) {
					return nil, nil
				} else {
					return nil, fmt.Errorf("pubkey does not match")
				}
			},
			// TODO isRevoked
		}

		// If no principals are expected, the only valid certs
		// are those valid for all principals (i.e. with an
		// empty valid_principals field)
		accepted := false
		if len(sk.Principals) == 0 {
			c := FakeConn{user: ""} // the empty principal is not a valid principal
			perms, err := checker.Authenticate(&c, parsedKey)
			if err != nil {
				log.Printf("checker.Authenticate: %v, skipping", err)
			} else if perms != nil && len(perms.CriticalOptions) > 0 {
				log.Printf("certificate has unsupported CriticalOptions, skipping")
			} else {
				accepted = true
			}
		} else {
			for _, p := range sk.Principals {
				c := FakeConn{user: p}
				perms, err := checker.Authenticate(&c, parsedKey)
				if err != nil {
					log.Printf("checker.Authenticate: %v, skipping", err)
					continue
				} else if perms != nil && len(perms.CriticalOptions) > 0 {
					log.Printf("certificate has unsupported CriticalOptions, skipping")
					continue
				} else {
					accepted = true
				}
			}
		}
		if accepted {
			return true
		}
	}
	// No authorized_key matched this agent key
	return false
}

// FilterCandidates iterates over all keys offered by the agent and
// returns the list of keys we might accept.
func (a AgentAuth) FilterCandidates() ([]*agent.Key, error) {
	var candidates []*agent.Key
	keys, err := a.Agent.List()
	if err != nil {
		return nil, err
	}
	for i, k := range keys {
		// TODO limit to max auth attempts
		log.Printf("Agent offers key %v type:%v goType:%v value:[%.40v]", i, k.Type(), reflect.TypeOf(k), k)
		if a.attemptCandidate(k) {
			candidates = append(candidates, k)
		}
	}
	return candidates, nil
}

// ChallengeKeys challenges the agent to prove they own the private
// key for each candidate until one succeeds (and returns true) or
// until there are no candidates remaining (and returns false)
func (a AgentAuth) ChallengeKeys(candidates []*agent.Key) (bool, error) {
	for _, k := range candidates {
		log.Printf("verifying agent key %v", k)
		challenge := []byte("hello world") // TODO
		sig, err := a.Agent.Sign(k, challenge)
		if err != nil {
			return false, err
		}

		result := k.Verify(challenge, sig)
		if result == nil {
			return true, nil
		} else {
			return false, fmt.Errorf("signature mismatch")
		}
	}
	return false, fmt.Errorf("no candidate key")
}

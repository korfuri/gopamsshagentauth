package gopamsshagentauth

import (
	// "crypto/rand"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slices"
	"log"
	"net"
	"os"
	"reflect"
)

var authorized_keys = []string{
	// ~/.ssh/id_rsa.pub
	// "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQjPjLr8UkWHBQc8G/FdAAJDSvVdLm2WUNV/evkOnfL1FEzgOIH/3QqE6ulRzh/c9VzLLDZh4wlKfZ9yebbEVoqBYNop0hMlDVZG3GXMl355FHHIxe9NMpJva4ce6OtEi5ymgyvhynv24UXmbU6hW/4eN8tVMcAgF0qKhtTC2NYVZj8D5UVv1jWymEWgHPxki3RAkxm5YIFVB72bn6vxBfASwX9T/TyN1pdWJXzbk31SMOzQYUlKSWYvZoFIAzObf6JXYatqnhjIzoIeX3auuJKOcGpspUvFcDgabKWrbMfmoO2ePUI5XFRM74JgS5EnQl1ABYBpej3NpENBj93RaZ korfuri@kelyus",
	// ecdsa-sk ./key
	// "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBDaR5qqYEAkTj1HesARmHbmhHeVCZOAUIDB3bPZBj3Y7ByFJoGXWZl7LT1h4uyRT7drZxW/qmCXcf6rNAPA6//gAAAAEc3NoOg== korfuri@kelyus",
	// ./key2.pub
	// "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO6qt7LY67KDBl+d5cRLG1vofsSQyiXCp8W+mbwN92o1TdcoKOwsGBRiSwBiVbVF2TDNaXzUv4QcZW9QeE4JRtk= korfuri@kelyus",
	// ca.pub as CA
	// "cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNId6CMSyOCyWRCipF8/mp2R5fwG5T5qdpQRbiTV6thVkjZl5znlNjwRrwAtvGCpszvDRSu3vueYWi021WGJg2U= korfuri@kelyus",
	"cert-authority,principals=\"sudoer,root\" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNId6CMSyOCyWRCipF8/mp2R5fwG5T5qdpQRbiTV6thVkjZl5znlNjwRrwAtvGCpszvDRSu3vueYWi021WGJg2U= korfuri@kelyus",
	// ca2.pub as CA
	// "cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZycAovA8cIQSvEJJze24R6OvJxOrRuHLcqjfHDvjHdWHKcjNrW/ssAAjPMIHSkC0jTAhcyf/pgP1lFHYEeSH4= korfuri@kelyus",
}

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

// LoadAuthorizedKeys parses all authorized_keys and returns them as
// an array of AuthorizedKey
func LoadAuthorizedKeys() ([]AuthorizedKey, error) {
	serverKeys := make([]AuthorizedKey, len(authorized_keys))
	for i, ak := range authorized_keys {
		pubKey, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(ak))
		if err != nil {
			return nil, err
		}
		if rest != nil {
			log.Printf("Unknown rest when parsing key %v, skipping: %v", ak, rest)
			continue
		}
		serverKeys[i] = AuthorizedKey{
			Key:           pubKey,
			CertAuthority: slices.Contains(options, "cert-authority"),
			Principals:    []string{}, // TODO
		}
	}
	return serverKeys, nil
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
		log.Printf("Can't unmarshal agent key %v, skipping", k)
		return false
	}

	c := FakeConn{user: "sudoer"} // TODO

	for _, sk := range a.AuthorizedKeys {
		//log.Printf("attempting agent key %v against server key %v", parsedKey, sk)
		checker := ssh.CertChecker{
			IsUserAuthority: func(k ssh.PublicKey) bool {
				log.Printf("in IsUserauthority")
				return bytes.Equal(k.Marshal(), sk.Key.Marshal())
			},
			UserKeyFallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
				log.Printf("in UserKeyfallback")
				if bytes.Equal(k.Marshal(), sk.Key.Marshal()) {
					return nil, nil
				} else {
					return nil, fmt.Errorf("pubkey does not match")
				}
			},
			// TODO isRevoked
		}

		perms, err := checker.Authenticate(&c, parsedKey)
		if err != nil {
			log.Printf("checker.Authenticate: %v, skipping", err)
			continue
		}
		if perms != nil && len(perms.CriticalOptions) > 0 {
			log.Printf("certificate has unsupported CriticalOptions, skipping")
			continue
		}
		// This authorized_key accepts this agent key!
		return true
	}
	// No authorized_key matched this agent key
	return false
}

// FilterCandidates iterates over all keys offered by the agent and
// returns the list of keys we might accept.
func (a AgentAuth) FilterCandidates() ([]*agent.Key, error) {
	var candidates []*agent.Key
	keys, err := a.Agent.List()
	log.Printf("keys: %v, err: %v", keys, err)
	if err != nil {
		return nil, err
	}
	for i, k := range keys {
		// TODO limit to max auth attempts
		log.Printf("Agent offers key %v type:%v goType:%v value:[%v]", i, k.Type(), reflect.TypeOf(k), k)
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

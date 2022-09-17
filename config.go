package gopamsshagentauth

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type AgentAuthConfig struct {
	AuthorizedKeysFile       string
	CAKeysFile               string
	AuthorizedPrincipals     string
	AuthorizedPrincipalsFile string
}

func NewAgentAuth(cfg AgentAuthConfig) (*AgentAuth, error) {
	if len(cfg.CAKeysFile) == 0 && (len(cfg.AuthorizedPrincipalsFile) > 0 || len(cfg.AuthorizedPrincipals) > 0) {
		return nil, fmt.Errorf("Invalid usage: authorized principals require a CA to be set")
	}
	if len(cfg.CAKeysFile) == 0 && len(cfg.AuthorizedKeysFile) == 0 {
		log.Printf("Warning: no authorized keys nor trusted CA, no identity will be accepted")
	}

	// Load ca_keys
	var authKeys []AuthorizedKey
	if len(cfg.CAKeysFile) > 0 {
		c, err := os.ReadFile(cfg.CAKeysFile)
		if err != nil {
			return nil, fmt.Errorf("Reading CA keys: %s", err)
		}
		authKeys, err = LoadUserCAKeys(c)
		if err != nil {
			return nil, fmt.Errorf("Loading CA keys: %s", err)
		}
	}
	var principals []string
	if len(cfg.AuthorizedPrincipals) > 0 {
		principals = strings.Split(cfg.AuthorizedPrincipals, ",")
	}
	if len(cfg.AuthorizedPrincipalsFile) > 0 {
		c, err := os.ReadFile(cfg.AuthorizedPrincipalsFile)
		if err != nil {
			return nil, fmt.Errorf("Reading principals file: %s", err)
		}
		p, err := LoadAuthorizedPrincipals(c)
		if err != nil {
			return nil, fmt.Errorf("Loading principals file: %s", err)
		}
		principals = append(principals, p...)
	}
	// Apply principal restrictions to all CA keys loaded so far
	for i := range authKeys {
		authKeys[i].Principals = principals
	}

	// Load authorized_keys
	if len(cfg.AuthorizedKeysFile) > 0 {
		c, err := os.ReadFile(cfg.AuthorizedKeysFile)
		if err != nil {
			return nil, fmt.Errorf("Reading authorized keys: %s", err)
		}
		ak, err := LoadAuthorizedKeys(c)
		if err != nil {
			return nil, fmt.Errorf("Loading authorized keys: %s", err)
		}
		authKeys = append(authKeys, ak...)
	}

	a := &AgentAuth{
		AuthorizedKeys: authKeys,
	}
	return a, nil
}

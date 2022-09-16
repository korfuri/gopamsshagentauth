package main

import (
	"flag"
	"log"
	"os"
	"strings"

	gpsa "github.com/korfuri/gopamsshagentauth"
)

var (
	authorized_keys_file       string
	ca_keys_file               string
	authorized_principals      string
	authorized_principals_file string
)

func init() {
	flag.StringVar(&authorized_keys_file, "k", "", "path to an authorized_keys file")
	flag.StringVar(&ca_keys_file, "c", "", "path to a TrustedUserCAKeys file")
	flag.StringVar(&authorized_principals, "p", "", "comma-separated list of authorized principals")
	flag.StringVar(&authorized_principals_file, "P", "", "path to a file containing a list of authorized principals")
}

func main() {
	flag.Parse()

	if len(ca_keys_file) == 0 && (len(authorized_principals_file) > 0 || len(authorized_principals) > 0) {
		log.Fatalf("Invalid usage: authorized principals require a CA to be set")
	}
	if len(ca_keys_file) == 0 && len(authorized_keys_file) == 0 {
		log.Printf("Warning: no authorized keys nor trusted CA, no identity will be accepted")
	}

	// Load ca_keys
	var authKeys []gpsa.AuthorizedKey
	if len(ca_keys_file) > 0 {
		c, err := os.ReadFile(ca_keys_file)
		if err != nil {
			log.Fatalf("Reading CA keys: %s", err)
		}
		authKeys, err = gpsa.LoadUserCAKeys(c)
		if err != nil {
			log.Fatalf("Loading CA keys: %s", err)
		}
	}
	var principals []string
	if len(authorized_principals) > 0 {
		principals = strings.Split(authorized_principals, ",")
	}
	if len(authorized_principals_file) > 0 {
		c, err := os.ReadFile(authorized_principals_file)
		if err != nil {
			log.Fatalf("Reading principals file: %s", err)
		}
		p, err := gpsa.LoadAuthorizedPrincipals(c)
		if err != nil {
			log.Fatalf("Loading principals file: %s", err)
		}
		principals = append(principals, p...)
	}
	// Apply principal restrictions to all CA keys loaded so far
	for i := range authKeys {
		authKeys[i].Principals = principals
	}

	// Load authorized_keys
	if len(authorized_keys_file) > 0 {
		c, err := os.ReadFile(authorized_keys_file)
		if err != nil {
			log.Fatalf("Reading authorized keys: %s", err)
		}
		ak, err := gpsa.LoadAuthorizedKeys(c)
		if err != nil {
			log.Fatalf("Loading authorized keys: %s", err)
		}
		authKeys = append(authKeys, ak...)
	}

	agent, closer, err := gpsa.GetAgentFromEnv()
	defer closer()
	if err != nil {
		log.Fatalf("GetAgentFromEnv: %v", err)
	}
	a := gpsa.AgentAuth{
		Agent:          agent,
		AuthorizedKeys: authKeys,
	}

	candidates, err := a.FilterCandidates()
	if err != nil {
		log.Fatalf("filterCandidates: %v", err)
	}

	result, err := a.ChallengeKeys(candidates)
	if err != nil {
		log.Fatalf("challengeKeys: %v", err)
	}
	if !result {
		log.Fatalf("Result: go away")
	} else {
		log.Printf("Result: welcome")
	}
}

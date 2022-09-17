package main

import (
	"flag"
	"log"

	gpsa "github.com/korfuri/gopamsshagentauth"
)

var cfg gpsa.AgentAuthConfig

func init() {
	flag.StringVar(&cfg.AuthorizedKeysFile, "k", "", "path to an authorized_keys file")
	flag.StringVar(&cfg.CAKeysFile, "c", "", "path to a TrustedUserCAKeys file")
	flag.StringVar(&cfg.AuthorizedPrincipals, "p", "", "comma-separated list of authorized principals")
	flag.StringVar(&cfg.AuthorizedPrincipalsFile, "P", "", "path to a file containing a list of authorized principals")
}

func main() {
	flag.Parse()

	a, err := gpsa.NewAgentAuth(cfg)
	if err != nil {
		log.Fatalf("NewAgentAuth: %s", err)
	}
	defer a.Close()

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

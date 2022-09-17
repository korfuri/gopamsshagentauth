package main

import (
	"flag"
	"log"

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

	a := gpsa.NewAgentAuthOrDie(authorized_keys_file, ca_keys_file, authorized_principals, authorized_principals_file)
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

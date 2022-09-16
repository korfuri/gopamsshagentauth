package main

import (
	"log"
	
	"github.com/korfuri/gopamsshagentauth"
)

func main() {
	ak, err := gopamsshagentauth.LoadAuthorizedKeys()
	if err != nil {
		log.Fatalf("loadAuthorizedkeys: %v", err)
	}
	a := gopamsshagentauth.AgentAuth{
		Agent: gopamsshagentauth.GetAgentOrDie(),
		AuthorizedKeys: ak,
	}
	//TODO defer ag.Close()

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

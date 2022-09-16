package main

import (
	"log"
	
	"github.com/korfuri/gopamsshagentauth"
)

var authorized_keys = `
## ~/.ssh/id_rsa.pub
# ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQjPjLr8UkWHBQc8G/FdAAJDSvVdLm2WUNV/evkOnfL1FEzgOIH/3QqE6ulRzh/c9VzLLDZh4wlKfZ9yebbEVoqBYNop0hMlDVZG3GXMl355FHHIxe9NMpJva4ce6OtEi5ymgyvhynv24UXmbU6hW/4eN8tVMcAgF0qKhtTC2NYVZj8D5UVv1jWymEWgHPxki3RAkxm5YIFVB72bn6vxBfASwX9T/TyN1pdWJXzbk31SMOzQYUlKSWYvZoFIAzObf6JXYatqnhjIzoIeX3auuJKOcGpspUvFcDgabKWrbMfmoO2ePUI5XFRM74JgS5EnQl1ABYBpej3NpENBj93RaZ korfuri@kelyus
## ecdsa-sk ./key
# sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBDaR5qqYEAkTj1HesARmHbmhHeVCZOAUIDB3bPZBj3Y7ByFJoGXWZl7LT1h4uyRT7drZxW/qmCXcf6rNAPA6//gAAAAEc3NoOg== korfuri@kelyus
## ./key2.pub
# ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO6qt7LY67KDBl+d5cRLG1vofsSQyiXCp8W+mbwN92o1TdcoKOwsGBRiSwBiVbVF2TDNaXzUv4QcZW9QeE4JRtk= korfuri@kelyus
## ca.pub as CA
# cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNId6CMSyOCyWRCipF8/mp2R5fwG5T5qdpQRbiTV6thVkjZl5znlNjwRrwAtvGCpszvDRSu3vueYWi021WGJg2U= korfuri@kelyus
cert-authority,principals="sudoer,root" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNId6CMSyOCyWRCipF8/mp2R5fwG5T5qdpQRbiTV6thVkjZl5znlNjwRrwAtvGCpszvDRSu3vueYWi021WGJg2U= korfuri@kelyus
## ca2.pub as CA
# "cert-authority ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZycAovA8cIQSvEJJze24R6OvJxOrRuHLcqjfHDvjHdWHKcjNrW/ssAAjPMIHSkC0jTAhcyf/pgP1lFHYEeSH4= korfuri@kelyus
`


func main() {
	ak, err := gopamsshagentauth.LoadAuthorizedKeys([]byte(authorized_keys))
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

package main

// #cgo LDFLAGS: -lpam
// #include <security/pam_modules.h>
// #include <security/pam_appl.h>
import "C"

import (
	"flag"
	"fmt"
	"log"
	"unsafe"

	gpsa "github.com/korfuri/gopamsshagentauth"
)

type PamHandle struct {
	p unsafe.Pointer
}

func (p PamHandle) ptr() *C.pam_handle_t {
	return (*C.pam_handle_t)(p.p)
}

func getHandle(h *C.pam_handle_t) PamHandle {
	return PamHandle{unsafe.Pointer(h)}
}

//export authenticate
func authenticate(handle *C.pam_handle_t, pamflags C.int, argv []string) C.int {
	fmt.Printf("authenticate: %v", argv)

	var cfg gpsa.AgentAuthConfig
	flags := flag.NewFlagSet("gopamsshagentauth", flag.PanicOnError)
	flags.StringVar(&cfg.AuthorizedKeysFile, "authorized_keys_file", "", "path to an authorized_keys file")
	flags.StringVar(&cfg.CAKeysFile, "ca_keys_file", "", "path to a TrustedUserCAKeys file")
	flags.StringVar(&cfg.AuthorizedPrincipals, "authorized_principals", "", "comma-separated list of authorized principals")
	flags.StringVar(&cfg.AuthorizedPrincipalsFile, "authorized_principals_file", "", "path to a file containing a list of authorized principals")

	for i := range argv {
		argv[i] = "--" + argv[i]
	}
	if err := flags.Parse(argv); err != nil {
		log.Fatalf("unable to parse flags")
	}

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
	return C.PAM_SUCCESS
}

func main() {
	panic("this is a shared library, not an executable binary")
}

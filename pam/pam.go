package main

// #cgo LDFLAGS: -lpam
// #include <security/pam_modules.h>
// #include <security/pam_appl.h>
import "C"

import (
	"fmt"
	"flag"
	"log"
	"unsafe"

	gpsa "github.com/korfuri/gopamsshagentauth"
)


type PamHandle struct {
	p unsafe.Pointer
}

func (p PamHandle) ptr() *C.pam_handle_t {
	return (*C.pam_handle_t)(p.p);
}

func getHandle(h *C.pam_handle_t) PamHandle {
	return PamHandle{unsafe.Pointer(h)}
}

//export authenticate
func authenticate(handle *C.pam_handle_t, pamflags C.int, argv []string) C.int {
	fmt.Printf("authenticate: %v", argv)

	var (
		authorized_keys_file       string
		ca_keys_file               string
		authorized_principals      string
		authorized_principals_file string
	)


	flags := flag.NewFlagSet("gopamsshagentauth", flag.PanicOnError)
	flags.StringVar(&authorized_keys_file, "authorized_keys_file", "", "path to an authorized_keys file")
	flags.StringVar(&ca_keys_file, "ca_keys_file", "", "path to a TrustedUserCAKeys file")
	flags.StringVar(&authorized_principals, "authorized_principals", "", "comma-separated list of authorized principals")
	flags.StringVar(&authorized_principals_file, "authorized_principals_file", "", "path to a file containing a list of authorized principals")

	for i := range argv {
		argv[i] = "--" + argv[i]
	}
	if err := flags.Parse(argv); err != nil {
		log.Fatalf("unable to parse flags")
	}
	
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
	return C.PAM_SUCCESS
}

func main() {
	panic("this is a shared library, not an executable binary")
}

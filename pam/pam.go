package main

// #cgo LDFLAGS: -lpam
// #include <security/pam_modules.h>
// #include <security/pam_appl.h>
import "C"

import (
	"flag"

	gpsa "github.com/korfuri/gopamsshagentauth"
)

//export authenticate
func authenticate(pamhandle *C.pam_handle_t, pamflags C.int, argv []string) C.int {
	var cfg gpsa.AgentAuthConfig
	flags := flag.NewFlagSet("gopamsshagentauth", flag.PanicOnError)
	flags.StringVar(&cfg.AuthorizedKeysFile, "authorized_keys_file", "", "path to an authorized_keys file")
	flags.StringVar(&cfg.CAKeysFile, "ca_keys_file", "", "path to a TrustedUserCAKeys file")
	flags.StringVar(&cfg.AuthorizedPrincipals, "authorized_principals", "", "comma-separated list of authorized principals")
	flags.StringVar(&cfg.AuthorizedPrincipalsFile, "authorized_principals_file", "", "path to a file containing a list of authorized principals")

	// PAM convention is to omit the dashes on flags. Add them back.
	for i := range argv {
		argv[i] = "--" + argv[i]
	}
	if err := flags.Parse(argv); err != nil {
		return C.PAM_SERVICE_ERR
	}

	a, err := gpsa.NewAgentAuth(cfg) // TODO we must drop euid here!
	if err != nil {
		return C.PAM_SERVICE_ERR // TODO should we make a difference
		// between errors loading keys and errors opening the agent socket?
	}
	defer a.Close()

	candidates, err := a.FilterCandidates()
	if err != nil {
		return C.PAM_AUTH_ERR
	}

	result, err := a.ChallengeKeys(candidates)
	if err != nil {
		return C.PAM_AUTH_ERR
	}
	if !result {
		return C.PAM_AUTH_ERR
	}

	if err != nil {
		return C.PAM_CONV_ERR
	}
	return C.PAM_SUCCESS
}

func main() {
	panic("this is a shared library, not an executable binary")
}

package main

// #cgo LDFLAGS: -lpam
// #include <security/pam_modules.h>
// #include <security/pam_appl.h>
// #include <sys/types.h>
import "C"

import (
	"flag"
	"fmt"
	"log/syslog"
	"syscall"
	"os"

	gpsa "github.com/korfuri/gopamsshagentauth"
)

func log(format string, args ...interface{}) {
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "gopamsshagentauth")
	if err != nil {
		return
	}
	l.Warning(fmt.Sprintf(format, args...))
}

//export c_log
func c_log(c *C.char) {
	log(C.GoString(c))
}

//export authenticate
func authenticate(pamhandle *C.pam_handle_t, uid C.uid_t, gid C.uid_t, argv []string) C.int {
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
		log("%s", err)
		return C.PAM_SERVICE_ERR
	}

	// Load the configuration before dropping privileges. This is
	// important because the authorized_keys may not be readable by
	// the requesting user.
	a, err := gpsa.NewAgentAuth(cfg)
	if err != nil {
		log("%s", err)
		return C.PAM_SERVICE_ERR
	}

	// Now, drop privileges before accessing the agent socket. This is
	// important because malicious user Mallory could point their
	// SSH_AUTH_SOCK to Alice's agent socket and try to elevate
	// privileges using Alice's keys.
	origEUID := os.Geteuid()
	origEGID := os.Getegid()
	if os.Getuid() != origEUID || origEUID == 0 {
		if err := syscall.Seteuid(int(uid)); err != nil {
			log("failed to drop euid from %d to %d", origEUID, uid)
			return C.PAM_AUTH_ERR
		}
		if err := syscall.Setegid(int(gid)); err != nil {
			log("failed to drop egid from %d to %d", origEGID, gid)
			return C.PAM_AUTH_ERR
		}
		defer func() {
			if err := syscall.Seteuid(origEUID); err != nil {
				log("failed to reset uid to %d", origEUID)
			}
			if err := syscall.Setegid(origEGID); err != nil {
				log("failed to reset gid to %d", origEGID)
			}
		}()
	}

	agent, closer, err := gpsa.GetAgentFromEnv()
	if err != nil {
		log("%s", err)
		return C.PAM_AUTH_ERR
	}
	defer closer()
	a.Agent = agent

	candidates, err := a.FilterCandidates()
	if err != nil {
		log("%s", err)
		return C.PAM_AUTH_ERR
	}

	result, err := a.ChallengeKeys(candidates)
	if err != nil {
		log("%s", err)
		return C.PAM_AUTH_ERR
	}
	if !result {
		return C.PAM_AUTH_ERR
	}
	return C.PAM_SUCCESS
}

func main() {
	panic("this is a shared library, not an executable binary")
}

package gopamsshagentauth

import (
	"golang.org/x/crypto/ssh"

	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	kPrincipalsOption    = "principals="
	kCertAuthorityOption = "cert-authority"
)

var hasSpaces = regexp.MustCompile(`\s`)

// LoadAuthorizedKeys parses the contents of an authorized_keys file
// and returns a list of AuthorizedKeys
func LoadAuthorizedKeys(contents []byte) ([]AuthorizedKey, error) {
	aks := []AuthorizedKey{}
	for len(contents) > 0 {
		pubKey, _, options, rest, err := ssh.ParseAuthorizedKey(contents)
		if err != nil {
			if err.Error() == "ssh: no key found" {
				// If we scanned to the end of the file and found no
				// keys, return what we've found so far
				return aks, nil
			}
			return nil, err
		}
		ak := AuthorizedKey{Key: pubKey}
		for _, opt := range options {
			if opt == kCertAuthorityOption {
				ak.CertAuthority = true
			} else if strings.HasPrefix(opt, kPrincipalsOption) {
				argValue := strings.TrimPrefix(opt, kPrincipalsOption)
				if strings.HasPrefix(argValue, `"`) {
					var err error
					argValue, err = strconv.Unquote(argValue)
					if err != nil {
						return nil, fmt.Errorf("error while parsing key: %s", err)
					}
				}
				ak.Principals = strings.Split(argValue, ",")
			} else {
				return nil, fmt.Errorf("unknown key option %s", opt)
			}
		}
		if len(ak.Principals) > 0 && !ak.CertAuthority {
			return nil, fmt.Errorf("key %.40v has principals %v but is not a cert-authority", ak.Key, ak.Principals)
		}
		aks = append(aks, ak)
		contents = rest
	}
	return aks, nil
}

// LoadUserCAKeys parses a file that contains public keys of
// certificate authorities. No options are allowed.
func LoadUserCAKeys(contents []byte) ([]AuthorizedKey, error) {
	aks, err := LoadAuthorizedKeys(contents)
	if err != nil {
		return nil, err
	}
	for i := range aks {
		if aks[i].CertAuthority || len(aks[i].Principals) > 0 {
			return nil, fmt.Errorf("options not supported in user CA files")
		}
		aks[i].CertAuthority = true
	}
	return aks, err
}

// LoadAuthorizedPrincipals loads an authorized_principals file, which
// just a list of line-separated principals, optionally prefixed by
// options. Since we support no options, we reject files containing
// options.
func LoadAuthorizedPrincipals(content []byte) ([]string, error) {
	lines := strings.Split(string(content), "\n")
	users := []string{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if len(l) == 0 {
			continue
		}
		if hasSpaces.Match([]byte(l)) {
			return nil, fmt.Errorf("options not supported for authorized principal %s", l)
		}
		users = append(users, l)
	}
	return users, nil
}

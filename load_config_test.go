package gopamsshagentauth_test

import (
	gpsa "github.com/korfuri/gopamsshagentauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	//"golang.org/x/crypto/ssh"

	//"bytes"
	//"crypto/rand"
	//"fmt"
	"testing"
)

func TestLoadAuthorizedPrincipals_basic(t *testing.T) {
	res, err := gpsa.LoadAuthorizedPrincipals([]byte(`
root
toor

# Comment
user
`))
	assert.NoError(t, err)
	assert.Equal(t, []string{"root", "toor", "user"}, res)
}

func TestLoadAuthorizedPrincipals_empty(t *testing.T) {
	res, err := gpsa.LoadAuthorizedPrincipals([]byte{})
	assert.NoError(t, err)
	assert.Equal(t, []string{}, res)
}

func TestLoadAuthorizedPrincipals_commentOnly(t *testing.T) {
	res, err := gpsa.LoadAuthorizedPrincipals([]byte("# Comment only"))
	assert.NoError(t, err)
	assert.Equal(t, []string{}, res)
}

func TestLoadAuthorizedPrincipals_options(t *testing.T) {
	res, err := gpsa.LoadAuthorizedPrincipals([]byte(`
root
restrict joey
`))
	assert.ErrorContains(t, err, "options not supported")
	assert.Empty(t, res)
}

func TestLoadAuthorizedKeys_empty(t *testing.T) {
	aks, err := gpsa.LoadAuthorizedKeys([]byte{})
	assert.NoError(t, err)
	assert.Empty(t, aks)
}

func TestLoadAuthorizedKeys_commentsOnly(t *testing.T) {
	aks, err := gpsa.LoadAuthorizedKeys([]byte(`
# Only comments!

# Empty otherwise

`))
	assert.NoError(t, err)
	assert.Empty(t, aks)
}

func TestLoadAuthorizedKeys_oneKey(t *testing.T) {
	aks, err := gpsa.LoadAuthorizedKeys([]byte(`
# One nice key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjr0u96cSREcSbYsVVurAj69DmiISH6fVFXqprSKkc1 user@host
`))
	assert.NoError(t, err)
	require.Len(t, aks, 1)
	assert.False(t, aks[0].CertAuthority)
	assert.Empty(t, aks[0].Principals)
}

func TestLoadAuthorizedKeys_oneCA(t *testing.T) {
	aks, err := gpsa.LoadAuthorizedKeys([]byte(`
# One beautiful CA
cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjr0u96cSREcSbYsVVurAj69DmiISH6fVFXqprSKkc1 user@host
# And some trailing comments
`))
	assert.NoError(t, err)
	require.Len(t, aks, 1)
	assert.True(t, aks[0].CertAuthority)
	assert.Empty(t, aks[0].Principals)
}

func TestLoadAuthorizedKeys_oneCAwithPrincipals(t *testing.T) {
	aks, err := gpsa.LoadAuthorizedKeys([]byte(`
# One beautiful CA with principal restrictions
cert-authority,principals="sudoer,admin,wheel,root" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjr0u96cSREcSbYsVVurAj69DmiISH6fVFXqprSKkc1 user@host
`))
	assert.NoError(t, err)
	require.Len(t, aks, 1)
	assert.True(t, aks[0].CertAuthority)
	assert.Equal(t, []string{"sudoer", "admin", "wheel", "root"}, aks[0].Principals)
}

func TestLoadAuthorizedKeys_twoEntries(t *testing.T) {
	aks, err := gpsa.LoadAuthorizedKeys([]byte(`
# A key and then the same key as a CA
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjr0u96cSREcSbYsVVurAj69DmiISH6fVFXqprSKkc1 user@host
cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjr0u96cSREcSbYsVVurAj69DmiISH6fVFXqprSKkc1 user@host
`))
	assert.NoError(t, err)
	require.Len(t, aks, 2)
	assert.False(t, aks[0].CertAuthority)
	assert.Empty(t, aks[0].Principals)
	assert.True(t, aks[1].CertAuthority)
	assert.Empty(t, aks[1].Principals)
	assert.Equal(t, aks[0].Key, aks[1].Key)
}

func TestLoadUserCAKeys_empty(t *testing.T) {
	res, err := gpsa.LoadUserCAKeys([]byte{})
	assert.NoError(t, err)
	assert.Empty(t, res)
}

func TestLoadUserCAKeys_twoCAs(t *testing.T) {
	res, err := gpsa.LoadUserCAKeys([]byte(`
# First CA
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjr0u96cSREcSbYsVVurAj69DmiISH6fVFXqprSKkc1 user@host
# Second CA
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbw7O5ZzZAIq7T4TzAmjpSXjl6b/8ufZkI1xxUuA0Qj
# Trailing comment
`))
	assert.NoError(t, err)
	require.Len(t, res, 2)
	assert.True(t, res[0].CertAuthority)
	assert.True(t, res[1].CertAuthority)
	assert.Empty(t, res[0].Principals)
	assert.Empty(t, res[1].Principals)
}

func TestLoadUserCAKeys_options(t *testing.T) {
	res, err := gpsa.LoadUserCAKeys([]byte(`
cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbw7O5ZzZAIq7T4TzAmjpSXjl6b/8ufZkI1xxUuA0Qj
`))
	assert.ErrorContains(t, err, "options not supported")
	assert.Empty(t, res)
}

func TestLoadUserCAKeys_optionPrincipals(t *testing.T) {
	res, err := gpsa.LoadUserCAKeys([]byte(`
principals=sudoer ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbw7O5ZzZAIq7T4TzAmjpSXjl6b/8ufZkI1xxUuA0Qj
`))
	assert.ErrorContains(t, err, "is not a cert-authority")
	assert.Empty(t, res)
}

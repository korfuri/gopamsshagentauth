package gopamsshagentauth_test

import (
	gpsa "github.com/korfuri/gopamsshagentauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func equalCandidates(t *testing.T, expect []ssh.PublicKey, actual []*agent.Key) {
	if assert.Equal(t, len(expect), len(actual), "candidates len mismatch") {
		for i := range expect {
			assert.True(t, bytes.Equal(expect[i].Marshal(), actual[i].Marshal()),
				"Candidate did not match the expected value.\n   Expected: [%s]\n   Actual: [%v]", ssh.MarshalAuthorizedKey(expect[i]), actual[i])
		}
	}
}

func TestFilterCandidates(t *testing.T) {
	type testcase struct {
		name             string
		agentKeys        []agent.AddedKey
		authorizedKeys   []gpsa.AuthorizedKey
		expectCandidates []ssh.PublicKey
	}

	// Create some certificates for our testcases
	user1_cert_by_ca := &ssh.Certificate{
		ValidPrincipals: []string{"user1", "sudoer"},
		Key:             testPublicKeys["user1"],
		SignatureKey:    testPublicKeys["ca"],
		ValidBefore:     ssh.CertTimeInfinity,
		CertType:        ssh.UserCert,
	}
	require.NoError(t, user1_cert_by_ca.SignCert(rand.Reader, testSigners["ca"]))
	user1_cert_by_ca_no_principals := &ssh.Certificate{
		ValidPrincipals: []string{},
		Key:             testPublicKeys["user1"],
		SignatureKey:    testPublicKeys["ca"],
		ValidBefore:     ssh.CertTimeInfinity,
		CertType:        ssh.UserCert,
	}
	require.NoError(t, user1_cert_by_ca_no_principals.SignCert(rand.Reader, testSigners["ca"]))
	user1_cert_unsigned := &ssh.Certificate{
		ValidPrincipals: []string{"user1", "sudoer"},
		Key:             testPublicKeys["user1"],
		SignatureKey:    testPublicKeys["ca"],
		ValidBefore:     ssh.CertTimeInfinity,
		CertType:        ssh.UserCert,
	}

	filterCandidateCases := []testcase{
		{
			name: "no agent keys, no authorized keys, no candidates",
		},
		{
			name:      "one agent key, no authorized keys, no candidates",
			agentKeys: []agent.AddedKey{{PrivateKey: testPrivateKeys["ed25519"], Comment: "ed25519"}},
		},
		{
			name:           "no agent keys, one authorized key, no candidates",
			authorizedKeys: []gpsa.AuthorizedKey{{Key: testPublicKeys["rsa"]}},
		},
		{
			name:             "one agent key, matching authorized key, one candidate",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["rsa"], Comment: "rsa"}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["rsa"]}},
			expectCandidates: []ssh.PublicKey{testPublicKeys["rsa"]},
		},
		{
			name:             "one agent cert, matching authorized CA, one candidate",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_by_ca}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ca"], CertAuthority: true, Principals: []string{"sudoer"}}},
			expectCandidates: []ssh.PublicKey{user1_cert_by_ca},
		},
		{
			name:             "one unsigned agent cert, matching authorized CA, no candidates",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_unsigned}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ca"], CertAuthority: true, Principals: []string{"sudoer"}}},
			expectCandidates: []ssh.PublicKey{},
		},
		{
			name:             "one agent cert, mismatched authorized CA, no candidates",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_unsigned}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ed25519"], CertAuthority: true, Principals: []string{"sudoer"}}},
			expectCandidates: []ssh.PublicKey{},
		},
		{
			name:             "one agent cert, CA key is authorized but not as a CA, no candidates",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_unsigned}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ca"], CertAuthority: false}},
			expectCandidates: []ssh.PublicKey{},
		},
		{
			name:             "one agent cert, matching authorized CA, mismatched principals, no candidate",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_by_ca}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ca"], CertAuthority: true, Principals: []string{"admin"}}},
			expectCandidates: []ssh.PublicKey{},
		},
		{
			// A principal-less cert can impersonate all
			// principals, cf PROTOCOL.certkeys
			name:             "one agent cert without principals, matching authorized CA but expecting a principal, one candidate",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_by_ca_no_principals}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ca"], CertAuthority: true, Principals: []string{"sudoer"}}},
			expectCandidates: []ssh.PublicKey{user1_cert_by_ca_no_principals},
		},
		{
			// If we're not expecting any principals, only
			// principal-less certs are accepted
			name:             "one agent cert without principals, matching authorized CA not expecting a principal, no candidates",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_by_ca_no_principals}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ca"], CertAuthority: true, Principals: []string{}}},
			expectCandidates: []ssh.PublicKey{user1_cert_by_ca_no_principals},
		},
		{
			name:             "one agent cert with princials, matching authorized CA expecting no principals, no candidate",
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys["user1"], Certificate: user1_cert_by_ca}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys["ca"], CertAuthority: true, Principals: []string{}}},
			expectCandidates: []ssh.PublicKey{},
		},

	}
	// Generate test cases for each private/public key loaded from
	// testdata.
	for keyname := range testPublicKeys {
		filterCandidateCases = append(filterCandidateCases, testcase{
			name:             fmt.Sprintf("checking compatiblity with key %s", keyname),
			agentKeys:        []agent.AddedKey{{PrivateKey: testPrivateKeys[keyname], Comment: keyname}},
			authorizedKeys:   []gpsa.AuthorizedKey{{Key: testPublicKeys[keyname]}},
			expectCandidates: []ssh.PublicKey{testPublicKeys[keyname]},
		})
	}

	for _, c := range filterCandidateCases {
		t.Run(c.name, func(t *testing.T) {
			ag := agent.NewKeyring()
			for _, k := range c.agentKeys {
				require.NoError(t, ag.Add(k))
			}
			a := gpsa.AgentAuth{
				Agent:          ag,
				AuthorizedKeys: c.authorizedKeys,
			}
			candidates, err := a.FilterCandidates()
			assert.NoError(t, err)
			equalCandidates(t, c.expectCandidates, candidates)
		})
	}
}

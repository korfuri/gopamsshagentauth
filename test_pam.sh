#!/usr/bin/env bash
set +xe

# colorecho echos a message in a given color and resets color
# afterwards
function colorecho() {
	tput setaf $1
	shift
	echo $*
	tput sgr0
}

# fail displays a message and exits
function fail() {
	colorecho 1 "$*"
	ssh-add -L
	exit 1
}

echo '== Test suite for go_pam_ssh_agent_auth.so'

# This should be run as: `ssh-agent ./test_pam.sh`. Check that we have
# an agent and that it's empty.
ssh-add -l -q 2>&1 | grep -q 'The agent has no identities.' || fail "Run this under ssh-agent"

# Check that we have our testing tools installed.
[ -x "$(command -v pam_test)" ] || fail "This test suite needs pam_test installed"
PAM_WRAPPER_SO=$(pkg-config --libs pam_wrapper) || fail "This test suite needs libpam_wrapper installed"

PAM_SSH_AGENT_AUTH_SO="$(pwd)/go_pam_ssh_agent_auth.so"
PAM_MATRIX_SO="$(dirname "${PAM_WRAPPER_SO?}")/pam_wrapper/pam_matrix.so"

D="$(mktemp -d)"
cd "${D?}"

mkdir pam.d

cat >passdb <<EOF
user1:password:pam_test
user2:password:pam_test
EOF
PASSDB="${D?}/passdb"

cat >pam.d/other <<EOF
account required ${PAM_MATRIX_SO?} passdb=${PASSDB?}
auth required ${PAM_MATRIX_SO?} passdb=${PASSDB?}
password required ${PAM_MATRIX_SO?} passdb=${PASSDB?}
session required ${PAM_MATRIX_SO?} passdb=${PASSDB?}
EOF

function run_test() {
	desc=$1
	want=$2
	shift 2
	pamopts="$*"
	colorecho 2 "== RUN test [$desc]"
	cat >pam.d/pam_test <<EOF
account required ${PAM_MATRIX_SO?} passdb=${PASSDB?}
auth required ${PAM_SSH_AGENT_AUTH_SO?} ${pamopts?}
password required ${PAM_MATRIX_SO?} passdb=${PASSDB?}
session required ${PAM_MATRIX_SO?} passdb=${PASSDB?}
EOF
	export PAM_WRAPPER=1
	export PAM_WRAPPER_SERVICE_DIR="${D?}/pam.d"
	export PAM_WRAPPER_DEBUGLEVEL=3  # changing this can help debug failures
	export PAM_SKIP_CHECK_CONFIG=1
	LD_PRELOAD="${PAM_WRAPPER_SO?}" pam_test auth user1
	result=$?
	[[ $result -eq $want ]] || fail "Test [$desc] should have returned $want, returned $result"
	colorecho 2 "== PASS test [$desc]"
}

ssh-keygen -q -N "" -t ed25519 -f ./user1
ssh-keygen -q -N "" -t ed25519 -f ./user2
ssh-keygen -q -N "" -t ed25519 -f ./ca1
ssh-keygen -q -N "" -t ed25519 -f ./ca2
cat ca1.pub ca2.pub > all_ca
cat user1.pub user2.pub > all_users
echo sudoer >> good_principals
echo root >> good_principals
echo cynthia >> other_principals
echo william >> other_principals
echo sam >> other_principals

# Test with simple keys
run_test "with authzd key but agent is empty" 7 "authorized_keys_file=${D?}/user1.pub"
ssh-add -q ./user1
run_test "with 1 authzd key, agent matches" 0 "authorized_keys_file=${D?}/user1.pub"
run_test "with multiple authzd keys, agent matching" 0 "authorized_keys_file=${D?}/all_users"
ssh-add -q ./user2
run_test "with 1 authzd key and agent has 2, 1 matching" 0 "authorized_keys_file=${D?}/user1.pub"
ssh-add -q -d ./user1
run_test "with 1 authzd key, agent has a diff one" 7 "authorized_keys_file=${D?}/user1.pub"
ssh-add -q ./user1
run_test "with 1 authzd key, agent has it, in a different slot this time" 0 "authorized_keys_file=${D?}/user1.pub"

# Test with a CA signing a principal-less cert
ssh-add -q -D
ssh-keygen -q -s ca1 -I user1 ./user1.pub
ssh-add -q ./user1
run_test "agent with a cert, CA is trusted as a key not as a CA" 7 "authorized_keys_file=${D?}/ca1.pub"
run_test "agent with a cert, CA trusted" 0 "ca_keys_file=${D?}/ca1.pub"
run_test "agent with a principal-less cert, CA trusted, principal expected" 0 "ca_keys_file=${D?}/ca1.pub authorized_principals=sudoer"

colorecho 2 "=="
colorecho 2 "== All PAM tests passed!"

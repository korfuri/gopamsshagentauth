#!/usr/bin/env bash

echo "Integration test suite for gopamsshagentauth"

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

# run_command runs the provided command and fails if its exit code is
# not what was expected
function run_command() {
	want=$1
	shift 1
	cmd="$*"
	colorecho 3 "== RUN: $*"
	$*
	result=$?
	[[ $result -eq $want ]] || fail "Command [$cmd] should have returned $want, returned $result"
	colorecho 2 "== PASS: $*"
}

TOOL=${1?}

# This should be run as: `ssh-agent ./test.sh`. Check that we have an
# agent and that it's empty.
ssh-add -l -q 2>&1 | grep -q 'The agent has no identities.' || fail "Run this under ssh-agent"

D="$(mktemp -d)"
cd "${D?}"

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

# No keys loaded, the tool should fail
run_command 1 $TOOL -k all_users
run_command 1 $TOOL -c all_ca
run_command 1 $TOOL -c all_ca -p sudoer

# With a key loaded
ssh-add -q ./user1
run_command 0 $TOOL -k all_users

# With a cert loaded (with principal)
ssh-add -q -D
ssh-keygen -q -s ca1 -I user1 -n sudoer ./user1.pub
ssh-add -q ./user1
run_command 0 $TOOL -c all_ca -p sudoer
run_command 1 $TOOL -c all_ca
run_command 0 $TOOL -c all_ca -P ./good_principals
run_command 1 $TOOL -c all_ca -P ./other_principals

# With a cert loaded (without principal)
ssh-add -q -D
ssh-keygen -q -s ca1 -I user1 ./user1.pub
ssh-add -q ./user1
run_command 0 $TOOL -c all_ca -p sudoer
run_command 0 $TOOL -c all_ca
run_command 0 $TOOL -c all_ca -P ./good_principals
run_command 0 $TOOL -c all_ca -P ./other_principals

# With an expired cert
ssh-add -q -D
ssh-keygen -q -s ca1 -I user1 -V -10m:-5m ./user1.pub
ssh-add -q ./user1
run_command 1 $TOOL -c ca1.pub -p sudoer
run_command 1 $TOOL -c ca1.pub
run_command 1 $TOOL -c ca1.pub -P ./good_principals
run_command 1 $TOOL -c ca1.pub -P ./other_principals

colorecho 2 '=='
colorecho 2 '== All CLI tests passed!'

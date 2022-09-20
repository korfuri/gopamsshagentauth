SRCS =	agent.go	\
		auth.go		\
		config.go	\
		load_config.go

SRCS_TEST =	auth_test.go		\
			load_config_test.go	\
			testdata_test.go

SRCS_PAM =	pam/pam.go pam/pam_adapter.c

go_pam_ssh_agent_auth.so: $(SRCS) $(SRCS_PAM)
	go build -buildmode c-shared -o go_pam_ssh_agent_auth.so ./pam

go_pam_ssh_agent_auth.h: go_pam_ssh_agent_auth.so

go_pam_ssh_agent_auth_cli: $(SRCS) cli/main.go
	go build -o go_pam_ssh_agent_auth_cli ./cli

all: go_pam_ssh_agent_auth_cli go_pam_ssh_agent_auth.so

clean:
	rm -f go_pam_ssh_agent_auth.so go_pam_ssh_agent_auth_cli go_pam_ssh_agent_auth.h

test_go:
	go test . ./cli ./pam

test_cli: cli/test.sh go_pam_ssh_agent_auth_cli
	ssh-agent ./cli/test.sh "$(shell pwd)/go_pam_ssh_agent_auth_cli"

test_pam: go_pam_ssh_agent_auth.so test_pam.sh
	ssh-agent ./test_pam.sh

test: test_go test_cli test_pam

.PHONY: all clean test test_go test_pam
.DEFAULT: go_pam_ssh_agent_auth.so

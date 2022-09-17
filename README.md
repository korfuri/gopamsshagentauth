# gopamsshagentauth

## gopamsshagentauth is a work-in-progress. It works but has not been reviewed, and its tests are limited.

gopamsshagentauth is a drop-in replacement for
[pam\_ssh\_agent\_auth](https://github.com/jbeverly/pam_ssh_agent_auth)
which offers several benefits:

* Supports all modern SSH key types, including FIDO-backed keys (`ecdsa-sk` and `ed25519-sk`);
* Supports SSH certificates;
* No rolling our own crypto, everything is based on `golang.org/x/crypto/ssh`
* Supports all flags supported by pam\_ssh\_agent\_auth

This can also be used as a substitute for [ussh](https://github.com/uber/pam-ussh). Unlike the latter, it supports keys and not just certs.

Currently, the project is half working. Here's the TODO list:

* Write integration tests [half-done!]
* Write proper usage documentation
* Get this reviewed by folks who know what they're doing

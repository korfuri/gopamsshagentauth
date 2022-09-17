{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  pam-test = pkgs.stdenv.mkDerivation {
    pname = "pam-test";
    version = "0.2019.11.11.0";

    src = fetchFromGitHub {
      owner = "pbrezina";
      repo = "pam-test";
      rev = "1f8270a82e91a7dff98365d7db8200b71eae61de";
      sha256 = "sha256-7JZwTlCpAugyFDAAplhhWn8h3Z3VQFRK7mbXGvRraYc=";
    };

    installPhase = ''
mkdir -p $out/bin
cp pam_test $out/bin/
'';

    buildInputs = [ pam ];
  };
in mkShell {
  nativeBuildInputs = [
    gdb
    go_1_18
    libpam-wrapper
    linux-pam
    pam-test
  ];
}

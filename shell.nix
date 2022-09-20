{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  pam-test = pkgs.stdenv.mkDerivation {
    pname = "pam-test";
    version = "0.2022.09.17.1";

    src = fetchFromGitHub {
      owner = "korfuri";
      repo = "pam-test";
      rev = "f734749de8ac6cb59a40297e6f614d6e6b475d67";
      sha256 = "sha256-/DRtu4yE0lcrCF5Rb9m7bILQKRRm40GbR/iM0MjXGtE=";
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
    pkg-config
  ];
}

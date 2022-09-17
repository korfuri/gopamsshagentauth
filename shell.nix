{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  pam-test = pkgs.stdenv.mkDerivation {
    pname = "pam-test";
    version = "0.2022.09.17.1";

    src = fetchFromGitHub {
      owner = "korfuri";
      repo = "pam-test";
      rev = "99093e7b718686865ee09dd2acee543e838bba6b";
      sha256 = "sha256-ApfEOlBtgo3xw2mgGU2no7HyecjCY7z8OMs18Sne4DE=";
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

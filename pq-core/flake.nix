{
  description = "Sovereign OS Deterministic Build Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        
        rustToolchain = pkgs.rust-bin.stable."1.77.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" "aarch64-apple-darwin" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            llvmPackages_17.llvm
            llvmPackages_17.clang
            cmake
            pkg-config
            openssl
            sqlite
          ];

          # Enforce exact reproducibility variables
          SOURCE_DATE_EPOCH = "315532800"; # 1980-01-01
          RUSTFLAGS = "-C target-cpu=generic -C codegen-units=1 -D warnings";
        };
      }
    );
}

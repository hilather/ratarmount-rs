{
  description = "ratarmount-rs archive filesystem and development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packageFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
        in pkgs.rustPlatform.buildRustPackage {
          pname = "ratarmount-rs";
          version = "0.1.34";
          src = self;
          cargoLock = {
            lockFile = ./Cargo.lock;
            allowBuiltinFetchGit = true;
          };
          cargoBuildFlags = [ "-p" "ratarmount" "--features" "nfsv4,sftp-russh" ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = with pkgs; [ fuse3 libarchive openssl sqlite zlib zstd ];
          doCheck = false;
          meta = with pkgs.lib; {
            description = "Mount archives as a filesystem with random access";
            homepage = "https://github.com/hilather/ratarmount-rs";
            license = licenses.mit;
            platforms = platforms.linux;
            mainProgram = "ratarmount";
          };
        };
    in {
      packages = forAllSystems (system: {
        default = packageFor system;
        ratarmount-rs = packageFor system;
      });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell {
          packages = with pkgs; [ rustc cargo rustfmt clippy pkg-config ];
          inputsFrom = [ (packageFor system) ];
        }; });
      overlays.default = final: prev: {
        ratarmount-rs = self.packages.${prev.system}.default;
      };
      checks = forAllSystems (system: {
        package = packageFor system;
      });
    };
}

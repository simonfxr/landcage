{
  description = "landcage - Landlock-based process sandbox";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      flib = flake-utils.lib;
      pkg =
        pkgs:
        pkgs.buildGo127Module {
          name = "landcage";
          version = "0.0.1";
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./go.mod
              ./go.sum
              (pkgs.lib.fileset.fileFilter (f: f.hasExt "go") ./.)
            ];
          };
          vendorHash = "sha256-YJv8ZGY+MyJHdUVazJliPmlxOkkSwcN6wM6TZjfzH1w=";
          env.CGO_ENABLED = "0";
          ldflags = [
            "-s"
            "-w"
          ];
          buildFlags = [ "-trimpath" ];
        };
    in
    flib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ ];
        };
      in
      rec {
        packages.default = packages.landcage;
        packages.landcage = pkg pkgs;
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_1_27
            pkgs.gopls
          ];
        };
      }
    )
    // {
      overlays.default = final: prev: { landcage = pkg final; };
    };
}

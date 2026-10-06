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
      srcFor =
        pkgs:
        pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            ./go.mod
            ./go.sum
            (pkgs.lib.fileset.fileFilter (f: f.hasExt "go") ./.)
          ];
        };
      pkg =
        pkgs:
        pkgs.buildGo127Module {
          name = "landcage";
          version = "0.0.1";
          src = srcFor pkgs;
          vendorHash = "sha256-YJv8ZGY+MyJHdUVazJliPmlxOkkSwcN6wM6TZjfzH1w=";
          env.CGO_ENABLED = "0";
          ldflags = [
            "-s"
            "-w"
          ];
          buildFlags = [ "-trimpath" ];
        };
      # Seatbelt is cgo and links libsandbox. pkgsCross.aarch64-darwin pulls a
      # from-source apple-sdk that does not build on this nixpkgs (libsbuf has
      # no meson.build). zig cc targets aarch64-macos and already provides
      # libSystem. libsandbox, libresolv, and CoreFoundation are stubs whose
      # install names are the macOS paths, so dyld loads the real ones on a Mac.
      # Go 1.26's darwin link line asks for CoreFoundation; Go 1.27 does not.
      # -s -w keeps the Go linker from invoking the host strip on the Mach-O.
      pkgDarwin =
        pkgs:
        pkgs.buildGo127Module {
          name = "landcage";
          version = "0.0.1";
          src = srcFor pkgs;
          vendorHash = "sha256-YJv8ZGY+MyJHdUVazJliPmlxOkkSwcN6wM6TZjfzH1w=";
          doCheck = false;
          env.CGO_ENABLED = "1";
          ldflags = [
            "-s"
            "-w"
          ];
          buildFlags = [ "-trimpath" ];
          nativeBuildInputs = [ pkgs.zig ];
          preBuild = ''
            export ZIG_LOCAL_CACHE_DIR=$TMPDIR/zig
            export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global
            mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR" stub
            cat > stub/empty.c <<'EOF'
            void landcage_link_stub(void) {}
            EOF
            zig cc -target aarch64-macos -shared -o stub/libsandbox.dylib stub/empty.c \
              -Wl,-install_name,/usr/lib/libsandbox.1.dylib
            zig cc -target aarch64-macos -shared -o stub/libresolv.dylib stub/empty.c \
              -Wl,-install_name,/usr/lib/libresolv.9.dylib
            mkdir -p stub/CoreFoundation.framework
            zig cc -target aarch64-macos -shared \
              -o stub/CoreFoundation.framework/CoreFoundation stub/empty.c \
              -Wl,-install_name,/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation
            export GOOS=darwin
            export GOARCH=arm64
            export CC="zig cc -target aarch64-macos"
            export CGO_LDFLAGS="-L$PWD/stub -F$PWD/stub"
          '';
          postInstall = ''
            if [ -f "$out/bin/darwin_arm64/landcage" ]; then
              mv "$out/bin/darwin_arm64/landcage" "$out/bin/landcage"
              rmdir "$out/bin/darwin_arm64"
            fi
          '';
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
        packages.landcage-aarch64-darwin = pkgDarwin pkgs;
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

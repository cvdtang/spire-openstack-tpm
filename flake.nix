{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          just
          libvirt         # virsh
          virt-manager    # virt-install
          cloud-utils     # cloud-localds
          qemu-utils      # qemu-img
          jq
          openssl
          curl
          openssh
          go
          gopls
          gotestsum
          cpio            # IPA ramdisk overlay
          xorriso
          unzip
          gettext         # envsubst
          openstackclient-full
          ansible
        ];
        # Keep Go's module/build caches inside the repo, not in $HOME.
        shellHook = ''
          export GOPATH="$(git rev-parse --show-toplevel 2>/dev/null || pwd)/.go"
          export GOCACHE="$GOPATH/cache"
          export GOTOOLCHAIN=local
          # openstackclient and ansible are wrapped and built on different Pythons; a shared PYTHONPATH breaks openstack.
          unset PYTHONPATH
        '';
      };
    };
}

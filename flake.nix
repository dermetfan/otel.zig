{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixpkgs-unstable;
    parts.url = github:hercules-ci/flake-parts;
    make-shell.url = github:nicknovitski/make-shell;
    treefmt-nix = {
      url = github:numtide/treefmt-nix;
      inputs.nixpkgs.follows = "nixpkgs";
    };
    inclusive = {
      url = github:input-output-hk/nix-inclusive;
      inputs.stdlib.follows = "parts/nixpkgs-lib";
    };
    utils = {
      url = github:dermetfan/utils.zig;
      inputs = {
        nixpkgs.follows = "nixpkgs";
        parts.follows = "parts";
        make-shell.follows = "make-shell";
        treefmt-nix.follows = "treefmt-nix";
        inclusive.follows = "inclusive";
      };
    };
  };

  outputs = inputs:
    inputs.parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux"];

      imports = [
        nix/checks.nix
        nix/devShells.nix
        nix/formatter.nix
        nix/hydraJobs.nix
      ];

      perSystem = {inputs', ...}: {
        _module.args.pkgs =
          inputs'.nixpkgs.legacyPackages.extend
          inputs.utils.overlays.zig;
      };
    };
}

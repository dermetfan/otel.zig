{
  inputs,
  config,
  ...
}: {
  imports = with inputs; [
    make-shell.flakeModules.default
  ];

  flake.shellModules.zig-protobuf = {
    lib,
    pkgs,
    ...
  }: {
    imports = [inputs.utils.shellModules.zig];

    shellHook = ''
      # If set, zig-protobuf respects this instead of downloading a binary.
      export PROTOC_PATH=${lib.getExe pkgs.protobuf}
    '';
  };

  perSystem.make-shells.default.imports = [config.flake.shellModules.zig-protobuf];
}

{inputs, ...}: {
  perSystem = {
    lib,
    pkgs,
    ...
  }: {
    checks.test = pkgs.buildZigPackage {
      src = inputs.inclusive.lib.inclusive ./.. [
        ../build.zig
        ../build.zig.zon
        ../src
      ];

      zigDepsHash = "sha256-f/wJqnPvkmJDeT+DYQjikSbtp4bhwMymDxZvUFHUqEM=";

      zigRelease = "ReleaseSafe";

      zigTarget = null;

      dontBuild = true;
      dontInstall = true;

      PROTOC_PATH = lib.getExe pkgs.protobuf;

      postCheck = ''
        touch $out
      '';
    };
  };
}

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

      zigDepsHash = "sha256-x6xjO4mdHOrgNky6EQuM2xwy0Wl9PzK0TJXmtBXJYws=";

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

{
  description = "Bitcoin DNS seeder";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        seeder = pkgs.rustPlatform.buildRustPackage {
          pname = "seeder";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          meta.mainProgram = "seeder";
        };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.seeder;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.seeder ];
          packages = [
            pkgs.rust-analyzer
            pkgs.clippy
            pkgs.rustfmt
            pkgs.dig
          ];
        };
      });

      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.seeder;
        in
        {
          options.services.seeder = {
            enable = lib.mkEnableOption "Bitcoin DNS seeder";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.seeder;
            };

            seedNode = lib.mkOption {
              type = lib.types.str;
              example = "1.2.3.4:8333";
              description = "Peer to bootstrap the crawler from.";
            };

            hostname = lib.mkOption {
              type = lib.types.str;
              example = "seed.example.com";
              description = "Hostname the nameserver is the authority for.";
            };

            nameserver = lib.mkOption {
              type = lib.types.str;
              example = "ns1.example.com";
            };

            hostmaster = lib.mkOption {
              type = lib.types.str;
              example = "admin.example.com";
            };

            port = lib.mkOption {
              type = lib.types.port;
              default = 53;
            };

            ttl = lib.mkOption {
              type = lib.types.ints.unsigned;
              default = 60;
            };

            answers = lib.mkOption {
              type = lib.types.ints.u16;
              default = 10;
              description = "Maximum number of records per response.";
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = true;
            };
          };

          config = lib.mkIf cfg.enable {
            networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

            services.resolved.settings.Resolve.DNSStubListener = lib.mkIf (cfg.port == 53) (
              lib.mkDefault false
            );

            environment.etc = lib.mkIf (
              config.services.resolved.enable
              && (config.services.resolved.settings.Resolve.DNSStubListener or null) == false
            ) { "resolv.conf".source = lib.mkOverride 90 "/run/systemd/resolve/resolv.conf"; };

            assertions =
              let
                conflicting = lib.filter (name: config.services.${name}.enable) [
                  "dnsmasq"
                  "unbound"
                  "bind"
                  "kresd"
                ];
              in
              [
                {
                  assertion = cfg.port != 53 || conflicting == [ ];
                  message = "services.seeder listens on port 53, which conflicts with services.${lib.concatStringsSep ", services." conflicting}. Disable them or set services.seeder.port.";
                }
              ];

            systemd.services.seeder = {
              description = "Bitcoin DNS seeder";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                ExecStart = lib.escapeShellArgs [
                  (lib.getExe cfg.package)
                  "--hostname"
                  cfg.hostname
                  "--nameserver"
                  cfg.nameserver
                  "--hostmaster"
                  cfg.hostmaster
                  "--port"
                  (toString cfg.port)
                  "--ttl"
                  (toString cfg.ttl)
                  "--answers"
                  (toString cfg.answers)
                  "--seed-node"
                  cfg.seedNode
                ];
                Restart = "always";
                RestartSec = 10;

                DynamicUser = true;
                AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
                CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [
                  "AF_INET"
                  "AF_INET6"
                ];
                RestrictNamespaces = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                SystemCallArchitectures = "native";
              };
            };
          };
        };
    };
}

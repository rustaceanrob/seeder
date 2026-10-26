# Deploying the seeder

The seeder ships as a Nix flake with a NixOS module (`services.seeder`). These steps take a fresh
VPS to a running, publicly reachable DNS seed.

Throughout, replace:

| Placeholder         | Meaning                                         |
| ------------------- | ----------------------------------------------- |
| `seed.example.com`  | The name clients will query for peers            |
| `ns1.example.com`   | The name of the server running the seeder        |
| `admin.example.com` | Hostmaster email, with `@` written as `.`        |
| `203.0.113.10`      | The server's public IPv4 address                 |

## Requirements

- A VPS with a public IPv4 address and root SSH access. Any distro is fine; step 2 replaces it
  with NixOS.
- UDP port 53 reachable from the internet. Check the provider's firewall or security groups.
- A local machine with Nix and flakes enabled.
- Control of the DNS zone for `example.com`.

## 1. Create a deployment flake

On your local machine, make a directory holding the server's configuration:

```sh
mkdir seeder-host && cd seeder-host
```

`flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    seeder.url = "github:rustaceanrob/seeder";
    seeder.inputs.nixpkgs.follows = "nixpkgs";
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { nixpkgs, seeder, disko, ... }:
    {
      nixosConfigurations.seed = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          disko.nixosModules.disko
          seeder.nixosModules.default
          ./configuration.nix
          ./disk.nix
        ];
      };
    };
}
```

`configuration.nix`:

```nix
{ modulesPath, ... }:
{
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];

  boot.loader.grub.enable = true;
  networking.hostName = "seed";

  services.openssh.enable = true;
  services.openssh.settings.PasswordAuthentication = false;
  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-ed25519 AAAA... you@laptop"
  ];

  services.seeder = {
    enable = true;
    seedNode = "199.231.213.124:8333";
    hostname = "seed.example.com";
    nameserver = "ns1.example.com";
    hostmaster = "admin.example.com";
  };

  system.stateVersion = "26.05";
}
```

When `port` is 53, the module turns off systemd-resolved's local stub listener so the seeder can
bind `0.0.0.0:53`. The host still resolves names through resolved. Enabling dnsmasq, unbound, bind
or kresd alongside the seeder on port 53 fails the build with an error.

Optional module settings and their defaults:

| Option         | Default | Meaning                                  |
| -------------- | ------- | ---------------------------------------- |
| `port`         | `53`    | UDP port to listen on                    |
| `ttl`          | `60`    | TTL of returned records                  |
| `answers`      | `10`    | Maximum addresses per response           |
| `openFirewall` | `true`  | Open `port` over UDP in the NixOS firewall |

`disk.nix` describes the disk layout. Check the device name on the VPS with `lsblk` (commonly
`/dev/sda` or `/dev/vda`):

```nix
{
  disko.devices.disk.main = {
    device = "/dev/sda";
    type = "disk";
    content = {
      type = "gpt";
      partitions = {
        boot = {
          size = "1M";
          type = "EF02";
        };
        root = {
          size = "100%";
          content = {
            type = "filesystem";
            format = "ext4";
            mountpoint = "/";
          };
        };
      };
    };
  };
}
```

This layout suits BIOS-boot VPSes. For a UEFI machine, swap the `boot` partition for a 512M
`EF00` partition mounted at `/boot` and use `boot.loader.systemd-boot.enable = true`.

Lock the inputs:

```sh
git init && git add . && nix flake lock
```

## 2. Install NixOS

[nixos-anywhere](https://github.com/nix-community/nixos-anywhere) installs the configuration
over SSH. It wipes the target disk.

```sh
nix run github:nix-community/nixos-anywhere -- --flake .#seed root@203.0.113.10
```

The machine reboots into NixOS with the seeder running.

If the server already runs NixOS, skip `disko` and `disk.nix`. Use the hardware configuration
from `/etc/nixos/hardware-configuration.nix` instead, then deploy with the command in step 5.

## 3. Check the service

```sh
ssh root@203.0.113.10 systemctl status seeder
ssh root@203.0.113.10 journalctl -u seeder -f
```

The log should show `Seeded with N network addresses` and `Listening on 0.0.0.0:53`. If the seed
peer is unreachable, the service restarts every 10 seconds until it connects. Set a different
`seedNode` if it keeps failing.

Query the server directly:

```sh
dig @203.0.113.10 seed.example.com A
```

An answer of `REFUSED` means the queried name doesn't match `hostname`. Answers fill out over
the first few minutes as the crawler finds reachable peers.

## 4. Delegate DNS

At the DNS provider for `example.com`, add:

```
ns1.example.com.   A    203.0.113.10
seed.example.com.  NS   ns1.example.com.
```

Once the records propagate, the seed resolves through normal DNS:

```sh
dig seed.example.com A
dig seed.example.com NS
```

## 5. Update

After pushing changes to the seeder, update the input and redeploy from the deployment flake:

```sh
nix flake update seeder
nixos-rebuild switch --flake .#seed --target-host root@203.0.113.10
```

Configuration changes deploy the same way, without the `nix flake update` step.

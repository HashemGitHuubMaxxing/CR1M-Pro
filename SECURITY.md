# Security & Licensing Policy

## Reporting Security Issues

If you discover a security vulnerability, memory safety bug, or crash in CR1M Pro Mod, please report it privately to **support@cr1m.net** with reproduction details rather than opening a public issue.

## Official Downloads & Binary Integrity

Official prebuilt binaries are distributed **exclusively** through **https://cr1m.net**. Any compiled executable distributed on GitHub Releases, third party websites, Discord servers, or Telegram channels is unofficial, unauthorized under the [CR1M Source Available License v1.0](LICENSE), and untrusted.

Before running a downloaded release, verify its **SHA256 checksum** against the official `v2.4.0` hashes published on **https://cr1m.net** (`certutil -hashfile "CR1M Pro.exe" SHA256`). Built in OTA updates also independently verify the RSA 2048 release manifest signature, exact byte length, PE64 header, and Windows CNG SHA256 digest before replacing the executable.

## Licensing & Copyright Enforcement

To report unauthorized redistribution of compiled binaries or modified forks, email **support@cr1m.net**.

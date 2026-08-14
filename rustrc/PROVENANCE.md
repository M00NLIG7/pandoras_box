# RustRC provenance record

## First-release decision

RustRC ships only source-built SSH/SFTP code. The release tree contains no Winexe container image, copied `winexe-static`/`libdl.so.2` binaries, embedded `runc`, compile-time downloader, or remote TCP transfer helper.

## Quarantined historical findings

The reviewed pre-release lineage contained:

- `winexe-static.tar.gz`, `winexe-static`, `winexe-static-2`, and `libdl.so.2` without an exact upstream source revision, reproducible build recipe, checksum manifest, component license/notice set, or source-offer record;
- a proc macro that downloaded a prerelease `runc` binary during compilation, accepted invalid TLS certificates, and did not verify an expected cryptographic digest; and
- Winexe and SSH fallback transfer paths that opened a remote listening TCP port.

Those materials were removed rather than redistributed. Their removal is not a legal conclusion about Winexe, Samba, glibc, or runc; it records that this repository lacked enough evidence for a releasable provenance chain. Historical Git/rescue refs may still retain the raw review lineage, but those objects are not release inputs.

## Reintroduction gate

Any future non-SSH transport or third-party binary must be reviewed as a separate product decision and include, before merge:

1. exact public source and immutable revision;
2. applicable license texts, notices, and source-offer obligations;
3. a reproducible source build using a pinned toolchain/container;
4. a checksum/SBOM manifest tied to the tested artifact;
5. no build-time network fetch or invalid-TLS bypass; and
6. security tests for authentication, bind scope, traversal, replay, cleanup, and failure behavior.

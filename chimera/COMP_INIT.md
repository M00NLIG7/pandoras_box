# Chimera collector contract

Chimera is the terminal inventory collector staged by Pandora. It is not a host-hardening agent and does not rotate credentials, install security services, change operating-system policy, download tools, or open an artifact-transfer listener.

## Release integration

```sh
chimera --output-root <directory> collector
```

Collector mode:

1. creates the selected local output directory;
2. gathers read-only inventory with bounded external probes;
3. writes valid Serde JSON to `inventory.json`;
4. writes diagnostic output to `application.log`; and
5. exits nonzero if the collector contract itself cannot complete.

An unavailable inventory subsection is represented in the JSON `sectionErrors` array rather than silently becoming complete data. Pandora retrieves both terminal files through its existing authenticated SFTP or SMB session and then records cleanup separately.

The standalone `inventory` subcommand is retained for local collector development. The first-release evidence and packaging path use `collector` mode only.

See the repository-local [`README.md`](../README.md), [`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md), and [`docs/BUILDING.md`](../docs/BUILDING.md) for the current product boundary. Historical hardening and credential-rotation descriptions are not part of this release.

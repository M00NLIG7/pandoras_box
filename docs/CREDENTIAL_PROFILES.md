# Credential profiles

Pandora resolves one named credential profile for each explicit target at runtime. Resolution is automatic and never prompts per host.

## Selection

A version 1 configuration has one optional fleet default, optional operating-system defaults, exact per-host overrides, and named profiles. Selection order is:

1. exact `host_overrides` entry;
2. matching `operating_system_defaults` entry;
3. `default_profile`.

Duplicate profile names, duplicate defaults for one operating system, or duplicate overrides for one host are ambiguous and fail closed. A missing profile, unsupported OS, unavailable authentication input, or transport-policy mismatch is a terminal `credentials` outcome for the affected host. Other hosts continue. Pandora never tries another profile, prompts, or weakens host-key/encryption policy.

```json
{
  "version": 1,
  "default_profile": "unix-agent",
  "operating_system_defaults": [
    { "operating_system": "windows", "profile": "windows-domain" }
  ],
  "host_overrides": [
    { "target": "192.0.2.10", "profile": "unix-breakglass-key" }
  ],
  "profiles": [
    {
      "name": "unix-agent",
      "operating_systems": [
        "linux", "freebsd", "openbsd", "netbsd", "dragonflybsd", "pfsense"
      ],
      "username": "root",
      "authentication": {
        "type": "ssh_agent",
        "public_key_sha256": "SHA256:<unpadded 43-character base64 digest>"
      },
      "transports": ["ssh_sftp"],
      "ssh_port": 22,
      "ssh_host_key_policy": "require_known"
    },
    {
      "name": "unix-breakglass-key",
      "operating_systems": ["linux"],
      "username": "operator",
      "authentication": {
        "type": "ssh_key",
        "private_key": "secrets/id_ed25519",
        "public_key_sha256": "SHA256:<unpadded 43-character base64 digest>"
      },
      "transports": ["ssh_sftp"],
      "ssh_port": 2222,
      "ssh_host_key_policy": "require_known"
    },
    {
      "name": "windows-domain",
      "operating_systems": ["windows"],
      "username": "pandora-operator",
      "authentication": {
        "type": "password",
        "source": {
          "type": "environment",
          "variable": "PANDORA_WINDOWS_PASSWORD"
        }
      },
      "transports": ["ssh_sftp", "windows_smb"],
      "ssh_port": 22,
      "smb_port": 445,
      "windows_domain": "BLUE",
      "windows_workstation": "PANDORA",
      "ssh_host_key_policy": "require_known"
    }
  ]
}
```

Paths are relative to the credential configuration file unless absolute. Configuration and target-contract files contain profile names and policy only—never password values.

## Authentication inputs

### External password

Use an injected environment variable:

```json
{"type":"password","source":{"type":"environment","variable":"PANDORA_UNIX_PASSWORD"}}
```

Or a protected file:

```json
{"type":"password","source":{"type":"file","path":"secrets/unix-password"}}
```

Password files must be regular non-link files and at most 4096 bytes. On Unix, the effective operator must own them and no group/other permission bits may be set. A trailing line ending is removed; embedded newlines and empty values are rejected. Pandora does not execute secret-provider commands or create a secret store. Have the existing provider inject the environment value or materialize the protected file before the mission.

### SSH private key

`ssh_key` requires both a protected private-key path and the expected OpenSSH `SHA256:` public-key fingerprint. Pandora rejects links, unsafe Unix ownership/modes, oversized files, encrypted keys that would require prompting, fingerprint mismatches, and RSA keys disabled by the current dependency policy. Validation happens before connecting to the target.

### SSH agent

`ssh_agent` requires one exact OpenSSH `SHA256:` fingerprint. Pandora connects to the existing OpenSSH agent (`SSH_AUTH_SOCK` on Unix; `SSH_AUTH_SOCK` or the standard OpenSSH named pipe on Windows), enumerates identities, and rejects missing or duplicate matches before contacting the target. Configure an unattended agent identity; Pandora never asks for a PIN, passphrase, or confirmation.

## Transport and host identity policy

A profile's `transports` is an allow-list intersected with the explicit target contract. A target is not authenticated unless the selected profile and target contract share a discovered transport. Profile ports are added to bounded discovery automatically. Pandora does not fall back to port 22 or another profile when a configured port is absent.

`ssh_host_key_policy` defaults to `require_known`. `dangerously_accept_unknown` is available only as an explicit profile policy and still rejects changed enrolled keys.

Windows domain/workstation fields are valid only on Windows password profiles. They domain-qualify the Windows SSH username and are passed as separate NTLM fields for SMB. SMB remains blocked before authentication until every remote-execution request can enforce the required encryption policy.

## Runtime and artifacts

Secrets are resolved lazily for a selected reachable host immediately before its host task, cached in redacting memory for the mission, and never written to logs, reports, inventories, mission state, or resume signatures. `mission.json` records only the selected profile name and a SHA-256 of its non-secret policy.

The approved mission behavior is unchanged:

- an existing ID errors by default;
- `--resume` requires the exact target, payload, deadline, and non-secret credential-policy identity;
- `--fresh` explicitly replaces prior state.

Rotating the value behind the same external secret source does not put a secret hash in artifacts. Changing a selected profile, source reference, username, port, transport, domain, key fingerprint, or host-key policy changes mission identity and blocks incompatible resume.

## Legacy one-secret compatibility

`--password-stdin` and `--password-file` remain a fast compatibility path. Pandora internally turns that one secret and the broad Unix/Windows usernames into named default profiles. This mode has no per-host credential overrides, key/agent selection, or Windows domain fields. It is mutually exclusive with `--credential-config`; use a versioned profile configuration for mixed fleets.

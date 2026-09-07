# Qualys QID Vulnerabilities

`qid` is a standalone command-line tool for looking up one Qualys QID across
all assets or against selected assets and, when explicitly requested, creating
an ignored-vulnerability exception. Normal lookups and ignored-state checks are
read-only. It has no runtime dependency on any other project.

## Requirements

- Python 3.12 or newer
- Qualys credentials with permission to read host detections
- Qualys exception-management permission only if using `--ignore`

## Install

From the project directory, run the installer. It copies the project into a
self-contained install directory, creates a private Python environment, and
puts a `qid` launcher in `~/.local/bin`:

```bash
./install.sh
```

The project and its private runtime files are installed by default at
`~/.local/share/qualys-qid-vulnerabilities`. To choose another location:

```bash
./install.sh /opt/qualys-qid-vulnerabilities /usr/local/bin
```

The installer creates `.env` from the template if it does not exist, never
overwrites an existing `.env`, and prints the next steps when it finishes.
The command can then be run from any directory because the launcher points it
back to the installed project:

```bash
qid --help
```

For a shorter help alias, `qid ?` is also supported.

Open the manual directly from the command:

```bash
qid --man
```

Display the command log without needing to locate the log file:

```bash
qid logs
```

To display a log written to a custom path, use `qid logs --log-file PATH`.

Set `QUALYS_BASE_URL` to the gateway for your Qualys service region, then set
either `QUALYS_USERNAME` and `QUALYS_PASSWORD` for basic authentication, or
`QUALYS_ACCESS_TOKEN` for token authentication. Timeouts are in
`config/runtime.toml`; the distributed configuration intentionally contains no
real service endpoint.

Non-secret runtime overrides may be exported as `QUALYS_BASE_URL`,
`QUALYS_AUTH_MODEL`, `QUALYS_TIMEOUT_SECONDS`, `QUALYS_RETRY_ATTEMPTS`,
`QUALYS_RETRY_BACKOFF_SECONDS`, and `QUALYS_VERIFY_SSL`.

Run the tests with:

```bash
python3 -m pytest -q
```

## Usage

An invocation may include a QID. With no QID, an explicit IP, Asset ID, or
DNS/hostname selector is required and `qid` lists all QIDs detected on that
device using the same table format. With a QID and no selector, it queries all
assets returned by Qualys. Use `qid --help` for the full option list.

Read-only lookup for one QID across all assets:

```bash
qid 12345
```

This may return a large result and can be slower than a scoped lookup. The
`--ignore` workflow always requires an explicit selector; an unscoped QID
lookup can never submit an ignore request.

Every normal command invocation writes readable, bounded diagnostics to the
private default log at `logs/qid.log` in the project directory. For the same
connection, status, timing, response-size, and error messages on stderr, use
verbose mode:

```bash
qid 12345 --ips "192.0.2.200" --verbose
```

Request bodies, credentials, and response content are never logged. Use
`--log-file PATH` to override the default location; the file rotates at 5 MiB
and keeps three backups (about 20 MiB maximum). Each invocation starts a
separate block marked with its QID and mode, with a blank line before it.

To show only assets where Qualys currently reports the QID as ignored:

```bash
qid 12345 --verify-ignored --ignored-only
```

This is read-only. `--verify-ignored` without `--ignored-only` shows all
returned detections and their ignored state.

Read-only lookup by IP address or range:

```bash
qid 12345 \
  --ips "192.0.2.87-192.0.2.92,192.0.2.200"
```

Read-only lookup by exact Qualys Asset ID or DNS/hostname:

```bash
qid 12345 --asset-ids "100001,100002"
qid 12345 --hostname "server-one.example.test"
```

When the QID is omitted, the selected device's complete returned detection
list is shown. Each row retains its Asset ID, IP, DNS/hostname, QID, status,
and Host Vulnerability ID, so different QIDs can be reviewed together.

# List every QID currently returned for one device:
```bash
qid --ip "192.0.2.10"
qid --asset-id 100001
qid --hostname "server-one.example.test"
```

Asset and hostname selectors first perform a read-only Qualys Host List lookup,
then query detections using only the exact IPs returned for matching assets.
Hostname matching is exact and case-insensitive, with a trailing dot ignored;
the tool does not perform local DNS resolution. `--ips`, `--asset-ids`, and
`--dns-hostnames` are mutually exclusive. `--host` is accepted as a short
alias for `--hostname`.

Verify ignored state without changing Qualys:

```bash
qid 12345 \
  --ips "192.0.2.1-192.0.2.2,192.0.2.65" \
  --verify-ignored
```

The ignore workflow is never implicit. It requires `--ignore`, an audit
comment, and the exact interactive confirmation `IGNORE QID <qid>`.

For a temporary ignore, set automatic reopening (1-730 days):

```bash
qid 12345 \
  --ips "192.0.2.5" \
  --ignore \
  --reopen-after-days 30 \
  --comment "Temporary vulnerability exception"
```

The selected reopen behavior and exact target scope are displayed before
confirmation. Omitting `--reopen-after-days` preserves the existing
indefinite-ignore behavior. Ranges are validated locally without being
expanded before the Qualys request.

## Configuration

By default, the tool reads `config/runtime.toml` and `.env` from the installed
project directory. This means `qid` can be run from any directory. Use
`--config-file` and `--env-file` to select alternate files.
Exported environment variables override matching `.env` values. Credentials
must not be placed in command-line arguments, committed files, or audit
comments.

For TLS-inspecting proxies such as Netskope, keep `verify_ssl = true` and set
`QUALYS_CA_BUNDLE` to a PEM bundle containing the approved proxy root CA. The
legacy `verify_ssl = false` option remains available for compatibility, but it
disables certificate verification and should be treated as an unsafe exception.

## Troubleshooting

- `omitting QID requires an explicit ... selector`: provide `--ips`,
  `--asset-ids`, or `--dns-hostnames` to list all QIDs for one device.
- `--ignore requires an explicit ... selector`: provide `--ips`, `--asset-ids`,
  or `--dns-hostnames` before using the state-changing ignore workflow. For a
  read-only estate-wide lookup, omit the selector; ranges use `start-end`
  notation.
- Authentication errors: check the configured auth model and required values
  in `.env` or the process environment.
- No matching assets: verify the exact Asset ID or DNS name in Qualys Host List.
- No detections: the supplied scope returned no matching detections for this
  QID; assets outside that scope were not inspected.
- Ignore errors: check the audit comment length (maximum 255 characters), the
  displayed target scope, the reopen setting, and the confirmation text.
- Network/TLS errors: verify the configured gateway is reachable and keep
  `verify_ssl = true`; use `QUALYS_CA_BUNDLE` for an approved TLS-inspecting
  proxy certificate.

## Man page

From a source checkout, read the included manual with:

```bash
man ./man/qualys-qid-vulnerabilities.1
```

The default installation includes the manual at the installed project path:

```bash
man -l ~/.local/share/qualys-qid-vulnerabilities/man/qualys-qid-vulnerabilities.1
```

If a custom install directory was used, replace the path accordingly. The
The manual command is also shown by `qid --help` and `qid ?`.

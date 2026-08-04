# Install and troubleshoot QuReddy

Install the `breachsafe-qureddy` distribution with Python 3.12 or newer. Use `pipx` for
the command line application or install into a managed virtual environment.
SSH scanning works without OpenSSL. TLS scanning requires a separate OpenSSL
3.5 LTS or newer binary.

## Contents

- [Prerequisites](#prerequisites)
- [Install with pipx](#install-with-pipx)
- [Install on macOS](#install-on-macos)
- [Install on Linux](#install-on-linux)
- [Install on Windows](#install-on-windows)
- [Install in a virtual environment](#install-in-a-virtual-environment)
- [Select OpenSSL for TLS](#select-openssl-for-tls)
- [Verify the installation](#verify-the-installation)
- [Upgrade or uninstall](#upgrade-or-uninstall)
- [Troubleshooting](#troubleshooting)
- [Related documentation](#related-documentation)

## Prerequisites

QuReddy requires:

- Python `>=3.12`
- macOS, Linux, or Windows
- network reachability to the target
- OpenSSL 3.5 LTS or newer for `scan tls` only

Check Python before installing:

```bash
python3.12 --version
```

On Windows PowerShell, use the Python launcher:

```powershell
py -3.12 --version
```

## Install with pipx

> **Pre-release (TestPyPI).** QuReddy 0.2.13 is being published to
> [TestPyPI](https://test.pypi.org/project/breachsafe-qureddy/) while the PyPI
> release is finalized. Until then, install from TestPyPI and pull runtime
> dependencies from PyPI:
>
> ```bash
> pipx install --python 3.12 \
>   --index-url https://test.pypi.org/simple/ \
>   --pip-args '--extra-index-url https://pypi.org/simple/' \
>   breachsafe-qureddy
> ```
>
> The commands below (plain `pipx install breachsafe-qureddy`) apply once the PyPI
> release is published.

If the resolver reports that no Click version satisfies `>=8.3.3`, the PyPI
fallback is missing. TestPyPI does not mirror QuReddy's runtime dependencies;
use the two-index command above and recreate any older pipx environment with
`pipx uninstall breachsafe-qureddy` before reinstalling.

The [pipx installation guide](https://pipx.pypa.io/stable/how-to/install-pipx.html)
provides current platform instructions. After `pipx` is available:

```bash
pipx ensurepath
pipx install breachsafe-qureddy
qureddy --version
```

Open a new terminal if `qureddy` is not found after `pipx ensurepath`.

QuReddy targets Python `>=3.12`. If your default `pipx` interpreter is
newer (for example 3.13), a bare `pipx install` fails with
`No matching distribution found`; pass `--python 3.12` (macOS/Linux) or use the
`py -3.12` launcher (Windows) as shown in the platform sections below.

## Install on macOS

Homebrew can install Python, pipx, and OpenSSL:

```bash
brew install python@3.12 pipx openssl@3.5
pipx ensurepath
pipx install --python "$(brew --prefix python@3.12)/bin/python3.12" breachsafe-qureddy
export QUREDDY_OPENSSL="$(brew --prefix openssl@3.5)/bin/openssl"
```

Do not select `/usr/bin/openssl`; current macOS systems expose LibreSSL at that
path, and QuReddy rejects LibreSSL for TLS scans.

## Install on Linux

Install Python 3.12 and pipx from the distribution's supported package source.
Then run:

```bash
pipx ensurepath
pipx install --python python3.12 breachsafe-qureddy
```

Distribution OpenSSL versions vary. Check the installed binary:

```bash
openssl version
openssl list -tls1_3 -tls-groups
```

If the version is older than 3.5.0 or the group list does not contain
`X25519MLKEM768`, install a supported vendor build or build a current release
from the [official OpenSSL source](https://openssl-library.org/source/).
Record the resulting path in `QUREDDY_OPENSSL`.

## Install on Windows

Install Python 3.12 and pipx, then run in PowerShell:

```powershell
py -3.12 -m pip install --user pipx
py -3.12 -m pipx ensurepath
py -3.12 -m pipx install breachsafe-qureddy
qureddy --version
```

For the TestPyPI rehearsal, use both indexes in PowerShell:

```powershell
py -3.12 -m pipx install `
  --index-url https://test.pypi.org/simple/ `
  --pip-args "--extra-index-url https://pypi.org/simple/" `
  breachsafe-qureddy
```

For TLS scans, install a trusted OpenSSL 3.5 LTS or newer Windows build. QuReddy
does not bundle or endorse a third party OpenSSL binary. Set the full path:

```powershell
$env:QUREDDY_OPENSSL = "C:\Path\To\OpenSSL\bin\openssl.exe"
& $env:QUREDDY_OPENSSL version
```

SSH scans do not need this step.

## Install in a virtual environment

Use this path when an application or CI job already manages an environment:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install breachsafe-qureddy
qureddy --version
```

On Windows PowerShell, activate with:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install breachsafe-qureddy
qureddy --version
```

Do not install into the operating system's managed Python environment.

## Select OpenSSL for TLS

QuReddy resolves the collector binary in this order:

1. `--openssl PATH`
2. `QUREDDY_OPENSSL`
3. `openssl` on `PATH`

Confirm both the version and required group:

```bash
"${QUREDDY_OPENSSL:-openssl}" version
"${QUREDDY_OPENSSL:-openssl}" list -tls1_3 -tls-groups
```

The selected binary must report OpenSSL 3.5.0 or newer and list
`X25519MLKEM768`.

## Verify the installation

The version and help commands are offline:

```bash
qureddy --version
qureddy scan ssh --help
qureddy scan tls --help
```

The first network check uses SSH and needs outbound TCP port 22:

```bash
qureddy scan ssh github.com --format json > github-ssh.json
```

Verify that the result is one JSON document:

```bash
python -m json.tool github-ssh.json > /dev/null
```

On PowerShell:

```powershell
qureddy scan ssh github.com --format json |
  Set-Content -Encoding utf8 github-ssh.json
Get-Content github-ssh.json | ConvertFrom-Json | Out-Null
```

## Upgrade or uninstall

For a pipx installation:

```bash
pipx upgrade breachsafe-qureddy
pipx uninstall breachsafe-qureddy
```

For a virtual environment:

```bash
python -m pip install --upgrade breachsafe-qureddy
python -m pip uninstall breachsafe-qureddy
```

## Troubleshooting

### `qureddy` is not found

Run `pipx ensurepath`, open a new terminal, and inspect:

```bash
pipx list
```

### Python version is rejected

The release metadata requires Python `>=3.12`. Point pipx at Python
3.12 explicitly:

```bash
pipx install --python python3.12 breachsafe-qureddy
```

### TLS scan exits 3

Exit `3` means the local OpenSSL dependency is missing, LibreSSL, too old,
broken, or lacks `X25519MLKEM768`. Run:

```bash
qureddy scan tls example.com -v
```

Then select a supported binary with `--openssl` or `QUREDDY_OPENSSL`.

### SSH scan exits 2

Exit `2` means the target could not be reached or its SSH identification or
KEXINIT response was malformed. Confirm DNS, the port, firewall rules, and
source IP allowlisting. Do not install OpenSSL for this failure; SSH scans do
not use it.

### Machine output does not parse

Do not combine explicitly requested verbose logs with standard output. Use:

```bash
qureddy scan ssh github.com --format json > scan.json 2> scan.log
```

Without `-v`, `-vv`, or `-vvv`, successful JSON and CBOM scans keep standard
error empty.

## Related documentation

- [Your first scan](../tutorials/your-first-scan.md)
- [CLI reference](../reference/cli.md)
- [Exit codes](../reference/exit-codes.md)
- [Scan SSH or SFTP](scan-ssh.md)
- [Generate and validate a CBOM](generate-a-cbom.md)

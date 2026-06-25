# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A set of Zabbix External Scripts plus importable Zabbix Templates for monitoring SSL/TLS
certificates and services. There is no build step, no test suite, and no package manager —
the "code" is two POSIX shell scripts and four Zabbix template XML files. Changes are validated
by importing templates into a Zabbix server and running the scripts against live SSL endpoints.

## Two checking modes

The repo offers two parallel approaches; understanding which one a change targets is the key
architectural distinction:

1. **One certificate per IP** — `usr/lib/zabbix/externalscripts/ssltls.check`, used by the
   non-discovery templates. Runs on the **Zabbix server (or proxy)** as an external script.
   Connects with `openssl s_client -connect HOST:PORT`. No SNI.

2. **Multiple certificates per IP (SNI)** — `usr/lib/zabbix/externalscripts/ssltls-sni.check`,
   used by `Template_App_HTTPS_Autodiscovery.xml`. Adds `-servername SNI-NAME` to the openssl
   call so the right cert is returned. The list of sites to check is driven by Low-Level
   Discovery: the **client agent** publishes `etc/zabbix/ssl_sites.json` via the
   `UserParameter=ssl.sites` defined in `etc/zabbix/zabbix_agentd.d/ssl-sites.conf`, and the
   discovery template expands `{#SSLNAME}`/`{#PORT}` into per-site items.

## The two scripts

Both scripts share the same structure: validate arg count → set `LC_ALL` → resolve
native-vs-STARTTLS → a big `case $CHECK_TYPE` dispatch. Each case runs one
`openssl s_client | openssl x509 -noout <opt>` pipeline and echoes a single value for Zabbix.

- `ssltls.check HOST:PORT METHOD CHECK_TYPE` — `#!/bin/bash`, handles IPv6 by bracketing the
  host (`[addr]:port`).
- `ssltls-sni.check HOST:PORT SNI-NAME METHOD CHECK_TYPE` — `#!/bin/sh` (plain POSIX), adds the
  SNI arg, and branches `date` parsing for FreeBSD/Darwin vs GNU. **`ssltls-sni.check` is the
  newer, more portable script** — non-SNI fixes often need to be ported here too.

`METHOD` is `native` (direct SSL/TLS, e.g. HTTPS/IMAPS) or a STARTTLS protocol from
`OPENSSL_PROTOS="smtp pop3 imap ftp xmpp"`.

`CHECK_TYPE` values: `simple` (1/0 up), `lifetime` (seconds until expiry — the main alerting
metric), `startdate`, `enddate`, `serial`, `fingerprint`, `subject`, `issuer`, `subject_hash`,
`issuer_hash`, `digestmode` (signature algorithm — used to detect SHA1/MD5 certs), `ssl3`
(1 = SSLv3 still enabled / Poodle-vulnerable), and `sni` (SNI/SAN DNS names, sni script only).

When adding a new check type, add a `case` arm to **both** scripts (where applicable) and a
corresponding item/trigger to the relevant template(s).

### Environment-specific edits users make
- **busybox `timeout`**: change `timeout_bin="/usr/bin/timeout"` to
  `timeout_bin="/usr/bin/timeout -t "` in the script(s). Mentioned in README; keep that note in sync.
- Binary paths (`echo_bin`, `timeout_bin`, `OPENSSL`) and `TIMEOUT` are hard-coded near the top
  of each script.

## Templates

All four template files are now on the **Zabbix 7.0 export format (YAML inside the `.xml`
file)**. The `.xml` extension is kept only so existing import workflows still find them; the
content is YAML, not XML.

- `Template_App_HTTPS_Service.xml` (1 template), `Template_App_FTP_Service.xml` (1 template),
  `Template_App_SSL_POP_IMAP_SMTP.xml` (**6 templates**: IMAP, IMAPS, POP3, POP3S, SMTP, SMTPS) —
  fixed-host checks keyed `ssltls.check[{HOST.CONN}:PORT,METHOD,CHECK_TYPE]`.
- `Template_App_HTTPS_Autodiscovery.xml` — LLD over `ssl.sites`, items keyed
  `ssltls-sni.check[{#SSLNAME}:{#PORT},{#SSLNAME},native,CHECK_TYPE]`. This is the reference
  template the others are modeled on.

Item-key strings inside templates must exactly match the argument order the scripts expect — a
mismatch silently yields no data.

Each service template carries the same shape (mirrored from the autodiscovery reference): a
service-up item + per-cert items (digestmode/enddate/lifetime/simple/ssl3/startdate), 9 triggers
(service-down, weak-signature **SHA1/MD5**, expired, 3 ranged expiry windows, **no-data**,
not-running, ssl3-poodle), a `Service state` valuemap, and one certificate-lifetime graph. There
is intentionally **no dashboard/overview page**. Triggers attach under the item their expression
references first. `ssl3` items ship `status: DISABLED`; `simple`/`ssl3` use a `BOOL_TO_DECIMAL`
preprocessing step.

Expiry thresholds are in seconds: `604800` = 7d, `1296000` = 15d, `2505600` = 29d (HTTPS/FTP and
the native mail services), `3888000` = 45d, `7776000` = 90d (the STARTTLS mail services). Windows
are ranged (`last()<HIGH and last()>LOW`) so only one severity fires at a time.

### Regenerating the fixed-host templates
The three fixed-host template files are emitted from a generator rather than hand-edited, so the
6 mail templates stay consistent. Run `python tools/gen_templates.py` (needs PyYAML); edit the
per-service model at the bottom of that script and re-run it rather than patching the YAML by
hand. PyYAML auto-quotes ambiguous scalars (e.g. `version: '7.0'`); avoid
reusing Python list/dict objects across items or it emits YAML anchors that Zabbix exports never
use.

Schema gotchas (Zabbix import is strict about these):
- Regular `graphs` are a **top-level** `zabbix_export.graphs` element, not a per-template key —
  nesting `graphs` under a template fails import with `unexpected marker "graphs"`. Graph items
  reference their template's items by `host` + `key`.
- `valuemaps` *do* live under each template; `triggers` are nested under the item their
  expression references first; `graph_prototypes` go under the discovery rule (autodiscovery
  template only).

## Manual verification

```sh
# non-SNI
usr/lib/zabbix/externalscripts/ssltls.check example.com:443 native lifetime
# SNI
usr/lib/zabbix/externalscripts/ssltls-sni.check example.com:443 example.com native enddate
```
Requires `openssl` and coreutils `timeout`/`date`. Exit 0 + a printed value = success;
exit 1 + empty/`0` = connect or parse failure.

## Conventions

- Update `README.md` when install steps, check types, or env-specific tweaks change.
- Scripts are POSIX `sh`/`bash`; preserve the existing `case`-arm style when extending.
- License is GPL2.

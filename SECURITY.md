# Security Policy

## Reporting a Vulnerability

If you discover a security issue, please **do not** open a public issue.
Report it privately via the repository's
[Security → Report a vulnerability](https://github.com/kekai2020/adguard-rules-merger-v8/security/advisories)
flow, or contact the maintainer. Please include:

- a description and reproduction steps,
- the affected version/commit,
- the platform and Python version,
- any proof-of-concept or logs.

You should receive an acknowledgement within a few days. Please give the
maintainer a reasonable remediation window before any public disclosure.

## Threat Model

The tool downloads third-party blocklists over HTTPS, compiles them into DNS
filter rules, and (optionally) queries third-party reputation services. Its
trust boundary is therefore the set of upstream list/API contents and the
local working directory.

## Design Guarantees

- **Transport security**: remote sources are fetched over HTTPS using
  `aiohttp`; the configuration validator rejects explicit URL schemes other
  than `http`/`https`/`file`. Local file paths are only read from the
  operator-supplied config.
- **No secret leakage**: API keys are read from `VIRUSTOTAL_API_KEY` /
  `OPENAI_API_KEY` and are never logged or written into `output/`, `stats.json`,
  reports, or cache metadata.
- **Report escaping**: HTML report interpolations are HTML-escaped, and JSON
  embedded in `<script>` blocks has `</` escaped so a hostile domain label
  cannot terminate the script or inject markup.
- **Fail closed on source outages**: when more than `fail_threshold` of
  enabled sources fail, the run aborts rather than publishing a partial or
  empty subscription.
- **Network layers degrade safely**: every audit layer that needs a network
  or an API key returns an explicit `disabled`/error state when unavailable;
  a single domain raising during the audit never aborts the whole batch.

## Known Considerations

- **Parsed-rule sidecar uses `pickle`** (`cache/parsed/`). The sidecar is a
  local build cache: it is only written by this program and read back from the
  local `cache/` directory. Treat the cache directory as trusted input — do
  not point `cache.directory` at a world-writable or untrusted share. The
  threat-intel blob cache (`feed_cache`) is JSON, not pickle.
- **Upstream content is not domain-validated for malicious intent** — the
  project assumes the configured upstream lists are authoritative; the
  whitelist multi-layer audit is the mitigation for suspicious allow rules.
- **Local file sources** (`file://` or relative/absolute paths) read arbitrary
  paths the operator configures; do not run an untrusted config file.
- **GitHub Actions auto-commit** relies on the scoped `GITHUB_TOKEN`; review
  changes to `.github/workflows/` carefully and keep the commit trigger
  path-limited.

## Hardening Checklist

- Pin your environment with `uv.lock` and use `uv sync --frozen`.
- Keep Python and dependencies up to date.
- Run with least-privilege filesystem access; keep `output/` and `cache/`
  outside directories served by unrelated applications.
- When mirroring outputs publicly, prefer a static directory or bucket
  serving the files verbatim.

# Publishing

How to release the four `sec-audit` distributions to PyPI. This is the operational runbook;
for the *why* behind the package split and dependency boundaries see
[`docs/components/packaging.md`](docs/components/packaging.md).

## Packages and order

The four distributions are versioned and released **together**, and must be built/uploaded in
dependency order so the inter-package version pins resolve when installing from PyPI:

```
sec-audit  →  sec-audit-logging  →  sec-audit-rules  →  django-sec-audit
```

| Distribution | Path | Depends on |
|---|---|---|
| `sec-audit` | `packages/sec-audit` | — |
| `sec-audit-logging` | `packages/sec-audit-logging` | `sec-audit` |
| `sec-audit-rules` | `packages/sec-audit-rules` | `sec-audit` |
| `django-sec-audit` | `packages/django-sec-audit` | `sec-audit`, `sec-audit-logging`, Django |

`django-sec-audit` does **not** depend on `sec-audit-rules`. Because the pins are
`>=X,<X+1`, you cannot `pip install django-sec-audit` from PyPI until its dependencies are
already published at a matching version.

## Prerequisites

```bash
source .venv/bin/activate
pip install build twine        # or: pip install -e "packages/django-sec-audit[dev]"
```

PyPI / TestPyPI accounts with API tokens. Prefer per-project tokens or
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/).

## 1. Bump the version

The version is declared inline in **all four** `pyproject.toml` files — bump them together so
they stay in sync:

```
packages/sec-audit/pyproject.toml
packages/sec-audit-logging/pyproject.toml
packages/sec-audit-rules/pyproject.toml
packages/django-sec-audit/pyproject.toml
```

The inter-package pins (`sec-audit>=0.1.0a1,<0.2`, etc.) must allow the new version — widen
the upper bound on a major/minor bump.

Then update [`CHANGELOG.md`](CHANGELOG.md): move `Unreleased` entries under the new version and
add the version's compare/tag links at the bottom.

## 2. Clean stale artifacts

Old wheels in a package's `dist/` will be uploaded by `twine upload dist/*`. Remove them first.
(`dist/` is git-ignored; e.g. `packages/django-sec-audit/dist/` may still hold pre-rename
`dj_sec_audit-0.3.0*` files on disk.)

```bash
rm -rf packages/*/dist
```

## 3. Build and validate each package

```bash
for pkg in sec-audit sec-audit-logging sec-audit-rules django-sec-audit; do
  python -m build packages/$pkg
  python -m twine check packages/$pkg/dist/*
done
```

`twine check` must pass for every package — it validates the metadata and that the README
renders as Markdown on PyPI. Confirm each artifact bundles its `LICENSE` and `README`:

```bash
python -m zipfile -l packages/sec-audit/dist/*.whl   # lists LICENSE + the module files
tar tzf packages/sec-audit/dist/*.tar.gz             # sdist contents
```

## 4. Dry run on TestPyPI

Upload in dependency order to TestPyPI first, then verify a clean install pulls the chain:

```bash
for pkg in sec-audit sec-audit-logging sec-audit-rules django-sec-audit; do
  python -m twine upload --repository testpypi packages/$pkg/dist/*
done

python -m venv /tmp/relcheck && /tmp/relcheck/bin/pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  "django-sec-audit[full]"
```

(The `--extra-index-url` lets third-party deps like Django/django-auditlog resolve from real PyPI.)

## 5. Upload to PyPI

Once TestPyPI looks correct, upload the same artifacts to PyPI in the same order:

```bash
for pkg in sec-audit sec-audit-logging sec-audit-rules django-sec-audit; do
  python -m twine upload packages/$pkg/dist/*
done
```

## 6. Tag the release

```bash
git tag v0.1.0a1
git push origin v0.1.0a1
```

Cut a GitHub release for the tag and paste the relevant `CHANGELOG.md` section.

## CI

`.github/workflows/ci.yml` already builds all four distributions, runs `twine check`, and
smoke-tests the wheels in a clean venv on every push. It does **not** publish — the upload steps
above are manual (or wire a `release`-triggered job using a PyPI Trusted Publisher).

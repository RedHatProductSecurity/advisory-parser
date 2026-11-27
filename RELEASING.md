# Release Procedure

This document describes how to cut and publish a new release of
`advisory-parser` to [PyPI](https://pypi.org/project/advisory-parser/).

Releases are performed manually; there is no release automation in CI. A
release consists of three parts that must stay in sync:

1. the package **version**, hardcoded in `setup.py` and in
   `advisory_parser/__init__.py`,
2. a **git tag** named `vX.Y` (e.g. `v1.16`), and
3. **distributions** (sdist + wheel) built from the tagged commit and
   uploaded to PyPI with `twine`.

## Versioning

- The version scheme is `MAJOR.MINOR` (e.g. `1.16`).
- Git tags are prefixed with `v`: version `1.16` ↔ tag `v1.16` (this matches
  all existing tags, `v1.4` through `v1.16`).
- The version is hardcoded in two places which **must be kept in sync**:
  - `setup.py` (`version="X.Y"`) — this is what gets baked into the PyPI
    distributions, and
  - `advisory_parser/__init__.py` (`__version__ = "X.Y"`) — this is what the
    installed package reports.

## Prerequisites

- Push access to the `master` branch of
  [RedHatProductSecurity/advisory-parser](https://github.com/RedHatProductSecurity/advisory-parser).
- Maintainer access to the
  [advisory-parser project on PyPI](https://pypi.org/project/advisory-parser/)
  and a PyPI API token (create one at pypi.org → *Account settings* →
  *API tokens*, scoped to the `advisory-parser` project).
- Build tooling in the environment you release from:

  ```bash
  pip install --upgrade build twine
  ```

## Release steps

### 1. Verify the release candidate

Make sure the `master` branch is in a releasable state:

- CI is green (the [Run CI](.github/workflows/main.yml) workflow runs
  `black --check` and the test suite via `tox` on every push to `master`), and
- a local test run passes:

  ```bash
  tox
  ```

### 2. Bump the version

Edit both files that carry the version:

- `setup.py`:

  ```python
  version="X.Y"
  ```

- `advisory_parser/__init__.py`:

  ```python
  __version__ = "X.Y"
  ```

### 3. Commit and tag

Commit the version bump to `master`, then create an annotated, `v`-prefixed
tag and push both:

```bash
git commit -am "Bump version to X.Y"
git push origin master
git tag -a vX.Y -m "Release vX.Y"
git push origin vX.Y
```

### 4. Build the distributions

Build from the tagged commit so the version baked into the artifacts matches
the tag:

```bash
git checkout vX.Y
rm -rf build dist advisory_parser.egg-info   # remove stale artifacts
python -m build
```

This produces:

- `dist/advisory_parser-X.Y.tar.gz` — the source distribution (contents
  controlled by `MANIFEST.in`), and
- `dist/advisory_parser-X.Y-py2.py3-none-any.whl` — the universal wheel
  (`[bdist_wheel] universal = 1` in `setup.cfg`).

(`python setup.py sdist bdist_wheel` still works but is deprecated.)

### 5. Check and upload to PyPI

Validate the metadata and README rendering first, then upload:

```bash
twine check dist/*
twine upload dist/*
```

When prompted for credentials:

- **username**: `__token__`
- **password**: your PyPI API token (`pypi-...`)

Alternatively, set the `TWINE_USERNAME` / `TWINE_PASSWORD` environment
variables or configure `~/.pypirc`.

### 6. Verify the release

Check the [PyPI project page](https://pypi.org/project/advisory-parser/) shows
the new version, then smoke-test it from a clean environment:

```bash
pip install --upgrade advisory-parser
python -c "import advisory_parser; print(advisory_parser.__version__)"
```

## Notes and troubleshooting

- **PyPI versions are immutable.** A given version number can be uploaded only
  once. If a release turns out to be broken, yank it from the PyPI project
  page and cut a new release with a bumped version.
- **Wrong version in the artifacts** almost always means the build ran from an
  un-bumped commit, a dirty worktree, or stale `dist/` files — rebuild from a
  clean checkout of the tag (step 4).
- **`twine check` failures** are usually caused by `README.rst` not rendering
  (it is used as the PyPI long description) — fix the RST and rebuild.
- **403 on upload** means the account or token lacks maintainer rights on the
  PyPI project, or the token was revoked or mis-scoped.

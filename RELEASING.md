# Releasing NetForensicAI

How to cut a release to [PyPI](https://pypi.org/project/netforensicai/). The
publish is automated (`.github/workflows/publish.yml`) via an API token; you
only bump the version, update the changelog, and tag.

## Prerequisites (one-time)

- **`PYPI_API_TOKEN` repository secret** must exist
  (Settings → Secrets and variables → Actions). Create the token at
  <https://pypi.org/manage/account/token/> (scope: `Project: netforensicai`
  now that the project exists), then set it — the most reliable way is the CLI,
  which avoids the web UI's wrong-tab pitfalls:

  ```bash
  gh secret set PYPI_API_TOKEN --repo Sh3n0bi/NetForensicAI
  # paste the pypi-... token at the masked prompt
  ```

  Verify it saved:

  ```bash
  gh api repos/Sh3n0bi/NetForensicAI/actions/secrets --jq '.total_count'   # -> 1
  ```

## Release checklist

1. **Bump the version** in `pyproject.toml` (`version = "X.Y.Z"`), following
   semver.
2. **Update `CHANGELOG.md`**: move the `[Unreleased]` items under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading.
3. **Green `main`**: ensure the `Tests` workflow (lint, the OS matrix,
   `wireshark`, `coverage`, `build-check`) is passing on the default branch.
4. **Sanity-check the build locally** (optional but cheap):

   ```bash
   python -m build
   python -m twine check dist/*
   ```

5. **Tag and release** — draft a GitHub Release
   (Releases → Draft a new release), create the tag `vX.Y.Z`, publish. The
   `release: published` event triggers `publish.yml`, which builds and uploads
   to PyPI.
6. **Verify it went live**:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/netforensicai/json   # 200
   pip index versions netforensicai
   ```

## Manual / recovery publish

`publish.yml` also has a **`workflow_dispatch`** trigger, so you can publish the
version currently in `pyproject.toml` without cutting a release
(Actions → Publish to PyPI → Run workflow, or `gh workflow run publish.yml`).
`skip-existing: true` means re-running for an already-published version is safe
— it is skipped, not an error.

If Actions is unavailable, publish from a machine that has the token:

```bash
python -m build
python -m twine upload dist/*        # username: __token__ , password: the pypi-... token
```

## Notes & gotchas (learned the hard way)

- **Token auth, not Trusted Publishing.** OIDC Trusted Publishing is the
  longer-term goal but was never configured on PyPI; the workflow uses an API
  token. To switch to OIDC later: register a publisher on PyPI, restore
  `permissions: id-token: write`, drop the `password:` input, and remove
  `attestations: false`.
- **`attestations: false`** is required with token auth — PEP 740 attestations
  need OIDC (`id-token: write`), which token auth does not have.
- **Keep `gh-action-pypi-publish` current.** Older versions bundle a `pkginfo`
  that cannot parse `Metadata-Version: 2.4` (emitted by modern setuptools) and
  fail with *"Metadata is missing required fields"*. Pin by commit SHA.
- **Never paste a token into chat, issues, or commits.** If one is exposed,
  revoke it immediately at <https://pypi.org/manage/account/token/>.

## Docker image

`docker.yml` publishes `ghcr.io/sh3n0bi/netforensicai` on pushes to the default
branch and on releases. New container packages are **private by default** — make
the package public once (GitHub → Packages → netforensicai → Package settings →
Danger Zone → Change visibility → Public) so `docker pull` works without a login.

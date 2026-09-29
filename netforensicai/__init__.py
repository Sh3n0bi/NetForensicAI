# Read from the installed distribution's metadata rather than hard-coded here:
# pyproject.toml is the single place the version is set, and a literal in this
# file silently stayed at 0.1.0 through two releases.
try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("netforensicai")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"

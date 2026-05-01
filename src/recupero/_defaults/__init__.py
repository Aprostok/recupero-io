"""Bundled default configuration files.

The YAML in this package is read via ``importlib.resources`` from
``recupero.config.load_config``. Putting it inside the package (rather
than at repo root) means a regular ``pip install`` makes it available
without any editable-install or path-trickery.
"""

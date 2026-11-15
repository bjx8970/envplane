"""Compatibility-free import alias for the shipped trusted SSH provider.

The startup loader reads plugins/ssh itself, so its code digest covers the real
provider implementation and manifest, not a wrapper importing outside the pack.
"""
from plugins.ssh.plugin import SSHPlugin

__all__ = ["SSHPlugin"]

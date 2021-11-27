"""A dataclass container for Guacamole connection parameters."""


# Standard Python Libraries
from dataclasses import dataclass


@dataclass
class ConnectionParameters:
    """A dataclass container for Guacamole connection parameters."""

    """The slots for this dataclass."""
    __slots__ = (
        "private_ssh_key",
        "rdp_password",
        "rdp_username",
        "vnc_password",
        "vnc_username",
        "windows_sftp_base",
    )

    """The private SSH key to use when transferring data via VNC."""
    private_ssh_key: str

    """The password to use when Guacamole establishes an RDP connection."""
    rdp_password: str

    """The user name to use when Guacamole establishes an RDP connection."""
    rdp_username: str

    """The password to use when Guacamole establishes a VNC connection."""
    vnc_password: str

    """The user name to use when Guacamole establishes a VNC connection."""
    vnc_username: str

    """The base path to use for configuring SFTP connections to Windows instances."""
    windows_sftp_base: str

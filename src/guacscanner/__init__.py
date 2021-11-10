"""The guacscanner library."""
# We disable a Flake8 check for "Module imported but unused (F401)"
# here because, although this import is not directly used, it
# populates the value package_name.__version__, which is used to get
# version information about this Python package.
from ._version import __version__  # noqa: F401
from .guacscanner import (
    add_instance_connection,
    add_user,
    check_for_ghost_instances,
    entity_exists,
    get_connection_name,
    get_entity_id,
    instance_connection_exists,
    main,
    process_instance,
    remove_connection,
    remove_instance_connections,
)

__all__ = [
    "add_instance_connection",
    "add_user",
    "check_for_ghost_instances",
    "entity_exists",
    "get_connection_name",
    "get_entity_id",
    "instance_connection_exists",
    "main",
    "process_instance",
    "remove_connection",
    "remove_instance_connections",
]

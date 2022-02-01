"""Query AWS for new (destroyed) instances and add (remove) Guacamole connections for them.

Also check for instances that have been destroyed and remove their
corresponding connections.

EXIT STATUS
  0   Update was successful.
  >0  An error occurred.

Usage:
  guacscanner [--log-level=LEVEL] [--oneshot] [--sleep=SECONDS] [--postgres-password=PASSWORD|--postgres-password-file=FILENAME] [--postgres-username=USERNAME|--postgres-username-file=FILENAME] [--private-ssh-key=KEY|--private-ssh-key-file=FILENAME] [--rdp-password=PASSWORD|--rdp-password-file=FILENAME] [--rdp-username=USERNAME|--rdp-username-file=FILENAME] [--region=REGION] [--vnc-password=PASSWORD|--vnc-password-file=FILENAME] [--vnc-username=USERNAME|--vnc-username-file=FILENAME] [--vpc-id=VPC_ID] [--windows-sftp-base=SFTPBASE|--windows-sftp-base-file=FILENAME]
  guacscanner (-h | --help)

Options:
  -h --help              Show this message.
  --log-level=LEVEL      If specified, then the log level will be set to
                         the specified value.  Valid values are "debug", "info",
                         "warning", "error", and "critical". [default: info]
  --oneshot              If present then the loop that adds (removes) connections for new (terminated) instances will only be run once.
  --postgres-password=PASSWORD    If specified then the specified value will be used as the password when connecting to the PostgreSQL database.  Otherwise, the password will be read from a local file.
  --postgres-password-file=FILENAME    The file from which the PostgreSQL password will be read. [default: /run/secrets/postgres-password]
  --postgres-username=USERNAME    If specified then the specified value will be used when connecting to the PostgreSQL database.  Otherwise, the username will be read from a local file.
  --postgres-username-file=FILENAME    The file from which the PostgreSQL username will be read. [default: /run/secrets/postgres-username]
  --private-ssh-key=KEY  If specified then the specified value will be used for the private SSH key.  Otherwise, the SSH key will be read from a local file.
  --private-ssh-key-file=FILENAME  The file from which the private SSH key will be read. [default: /run/secrets/private-ssh-key]
  --rdp-password=PASSWORD  If specified then the specified value will be used for the RDP password.  Otherwise, the password will be read from a local file.
  --rdp-password-file=FILENAME  The file from which the RDP password will be read. [default: /run/secrets/rdp-password]
  --rdp-username=USERNAME  If specified then the specified value will be used for the RDP username.  Otherwise, the username will be read from a local file.
  --rdp-username-file=FILENAME  The file from which the RDP username will be read. [default: /run/secrets/rdp-username]
  --region=REGION  The AWS region in which the VPC specified by --vpc-id exists.  Unused if --vpc-id is not specified. [default: us-east-1]
  --sleep=SECONDS  Sleep for the specified number of seconds between executions of the Guacamole connection update loop. [default: 60]
  --vnc-password=PASSWORD  If specified then the specified value will be used for the VNC password.  Otherwise, the password will be read from a local file.
  --vnc-password-file=FILENAME  The file from which the VNC password will be read. [default: /run/secrets/vnc-password]
  --vnc-username=USERNAME  If specified then the specified value will be used for the VNC username.  Otherwise, the username will be read from a local file.
  --vnc-username-file=FILENAME  The file from which the VNC username will be read. [default: /run/secrets/vnc-username]
  --vpc-id=VPC_ID        If specified then query for EC2 instances created
                         or destroyed in the specified VPC ID.  If not
                         specified then the ID of the VPC in which the host
                         resides will be used.
  --windows-sftp-base=SFTPBASE  If specified then the specified value will be used as the base path for configuring Windows SFTP connections.  Otherwise, the path will be read from a local file.
  --windows-sftp-base-file=FILENAME  The file from which the base path for Windows SFTP connections will be read. [default: /run/secrets/windows-sftp-base]
"""


# Standard Python Libraries
import datetime
import hashlib
import logging
import re
import secrets
import string
import sys
import time

# Third-Party Libraries
import boto3
import docopt
from ec2_metadata import ec2_metadata
import psycopg
from schema import And, Optional, Or, Schema, SchemaError, Use

from .ConnectionParameters import ConnectionParameters
from ._version import __version__

# TODO: Add exception handling for all the database accesses and
# wherever else it is appropriate.  guacscanner currently just bombs
# out if an exception is thrown, but it would probably make more sense
# to print an error message and keep looping, keepin' the train
# a-chooglin'.  See cisagov/guacscanner#5 for more details.

# TODO: Create command line options with defaults for these variables.
# See cisagov/guacscanner#2 for more details.
DEFAULT_ADD_INSTANCE_STATES = [
    "running",
]
DEFAULT_PASSWORD_LENGTH = 32
DEFAULT_PASSWORD_SALT_LENGTH = 32
DEFAULT_POSTGRES_DB_NAME = "guacamole_db"
DEFAULT_POSTGRES_HOSTNAME = "postgres"
DEFAULT_POSTGRES_PORT = 5432
DEFAULT_REMOVE_INSTANCE_STATES = [
    "terminated",
]
DEFAULT_AMI_SKIP_REGEXES = [
    re.compile(r"^guacamole-.*$"),
    re.compile(r"^nessus-.*$"),
    re.compile(r"^samba-.*$"),
]

# A precompiled regex
VPC_ID_REGEX = re.compile(r"^vpc-([0-9a-f]{8}|[0-9a-f]{17})$")

# TODO: Determine if we can use f-strings instead of .format() for
# these queries.  Also define the psycopg.sql.Identifier() variables
# separately so that they can be reused where that is possible.  See
# cisagov/guacscanner#3 for more details.

# The PostgreSQL queries used for adding and removing connections
COUNT_QUERY = psycopg.sql.SQL(
    "SELECT COUNT({id_field}) FROM {table} WHERE {name_field} = %s AND {value_field} = %s"
).format(
    id_field=psycopg.sql.Identifier("connection_id"),
    table=psycopg.sql.Identifier("guacamole_connection_attribute"),
    name_field=psycopg.sql.Identifier("attribute_name"),
    value_field=psycopg.sql.Identifier("attribute_value"),
)
IDS_QUERY = psycopg.sql.SQL(
    "SELECT {id_field} FROM {table} WHERE {name_field} = %s AND {value_field} = %s"
).format(
    id_field=psycopg.sql.Identifier("connection_id"),
    table=psycopg.sql.Identifier("guacamole_connection_attribute"),
    name_field=psycopg.sql.Identifier("attribute_name"),
    value_field=psycopg.sql.Identifier("attribute_value"),
)
ALL_IDS_QUERY = psycopg.sql.SQL(
    "SELECT {id_field}, {value_field} FROM {table} WHERE {name_field} = %s"
).format(
    id_field=psycopg.sql.Identifier("connection_id"),
    table=psycopg.sql.Identifier("guacamole_connection_attribute"),
    name_field=psycopg.sql.Identifier("attribute_name"),
    value_field=psycopg.sql.Identifier("attribute_value"),
)
INSERT_CONNECTION_QUERY = psycopg.sql.SQL(
    """INSERT INTO {table} (
    {name_field}, {protocol_field}, {max_connections_field},
    {max_connections_per_user_field}, {proxy_port_field}, {proxy_hostname_field},
    {proxy_encryption_method_field})
    VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING {id_field};"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection"),
    name_field=psycopg.sql.Identifier("connection_name"),
    protocol_field=psycopg.sql.Identifier("protocol"),
    max_connections_field=psycopg.sql.Identifier("max_connections"),
    max_connections_per_user_field=psycopg.sql.Identifier("max_connections_per_user"),
    proxy_port_field=psycopg.sql.Identifier("proxy_port"),
    proxy_hostname_field=psycopg.sql.Identifier("proxy_hostname"),
    proxy_encryption_method_field=psycopg.sql.Identifier("proxy_encryption_method"),
    id_field=psycopg.sql.Identifier("connection_id"),
)
INSERT_CONNECTION_PARAMETER_QUERY = psycopg.sql.SQL(
    """INSERT INTO {table}
    ({id_field}, {parameter_name_field}, {parameter_value_field})
    VALUES (%s, %s, %s);"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection_parameter"),
    id_field=psycopg.sql.Identifier("connection_id"),
    parameter_name_field=psycopg.sql.Identifier("parameter_name"),
    parameter_value_field=psycopg.sql.Identifier("parameter_value"),
)
INSERT_CONNECTION_ATTRIBUTE_QUERY = psycopg.sql.SQL(
    """INSERT INTO {table}
    ({id_field}, {attribute_name_field}, {attribute_value_field})
    VALUES (%s, %s, %s);"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection_attribute"),
    id_field=psycopg.sql.Identifier("connection_id"),
    attribute_name_field=psycopg.sql.Identifier("attribute_name"),
    attribute_value_field=psycopg.sql.Identifier("attribute_value"),
)
DELETE_CONNECTIONS_QUERY = psycopg.sql.SQL(
    """DELETE FROM {table} WHERE {id_field} = %s;"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection"),
    id_field=psycopg.sql.Identifier("connection_id"),
)
DELETE_CONNECTION_PARAMETERS_QUERY = psycopg.sql.SQL(
    """DELETE FROM {table} WHERE {id_field} = %s;"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection_parameter"),
    id_field=psycopg.sql.Identifier("connection_id"),
)
DELETE_CONNECTION_ATTRIBUTES_QUERY = psycopg.sql.SQL(
    """DELETE FROM {table} WHERE {id_field} = %s;"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection_attribute"),
    id_field=psycopg.sql.Identifier("connection_id"),
)

# The PostgreSQL queries used for adding and removing users
ENTITY_COUNT_QUERY = psycopg.sql.SQL(
    "SELECT COUNT({id_field}) FROM {table} WHERE {name_field} = %s AND {type_field} = %s"
).format(
    id_field=psycopg.sql.Identifier("entity_id"),
    table=psycopg.sql.Identifier("guacamole_entity"),
    name_field=psycopg.sql.Identifier("name"),
    type_field=psycopg.sql.Identifier("type"),
)
ENTITY_ID_QUERY = psycopg.sql.SQL(
    "SELECT {id_field} FROM {table} WHERE {name_field} = %s AND {type_field} = %s"
).format(
    id_field=psycopg.sql.Identifier("entity_id"),
    table=psycopg.sql.Identifier("guacamole_entity"),
    name_field=psycopg.sql.Identifier("name"),
    type_field=psycopg.sql.Identifier("type"),
)
INSERT_ENTITY_QUERY = psycopg.sql.SQL(
    """INSERT INTO {table} (
    {name_field}, {type_field})
    VALUES (%s, %s) RETURNING {id_field};"""
).format(
    table=psycopg.sql.Identifier("guacamole_entity"),
    name_field=psycopg.sql.Identifier("name"),
    type_field=psycopg.sql.Identifier("type"),
    id_field=psycopg.sql.Identifier("entity_id"),
)
INSERT_USER_QUERY = psycopg.sql.SQL(
    """INSERT INTO {table} (
    {id_field}, {hash_field}, {salt_field}, {date_field})
    VALUES (%s, %s, %s, %s);"""
).format(
    table=psycopg.sql.Identifier("guacamole_user"),
    id_field=psycopg.sql.Identifier("entity_id"),
    hash_field=psycopg.sql.Identifier("password_hash"),
    salt_field=psycopg.sql.Identifier("password_salt"),
    date_field=psycopg.sql.Identifier("password_date"),
)
# The PostgreSQL queries used to add and remove connection
# permissions
INSERT_CONNECTION_PERMISSION_QUERY = psycopg.sql.SQL(
    """INSERT INTO {table} (
    {entity_id_field}, {connection_id_field}, {permission_field})
    VALUES (%s, %s, %s);"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection_permission"),
    entity_id_field=psycopg.sql.Identifier("entity_id"),
    connection_id_field=psycopg.sql.Identifier("connection_id"),
    permission_field=psycopg.sql.Identifier("permission"),
)
DELETE_CONNECTION_PERMISSIONS_QUERY = psycopg.sql.SQL(
    """DELETE FROM {table} WHERE {connection_id_field} = %s;"""
).format(
    table=psycopg.sql.Identifier("guacamole_connection_permission"),
    connection_id_field=psycopg.sql.Identifier("connection_id"),
)


def entity_exists(db_connection, entity_name, entity_type):
    """Return a boolean indicating whether an entity with the specified name and type exists."""
    with db_connection.cursor() as cursor:
        logging.debug(
            "Checking to see if an entity named %s of type %s exists in the database.",
            entity_name,
            entity_type,
        )
        cursor.execute(ENTITY_COUNT_QUERY, (entity_name, entity_type))
        count = cursor.fetchone()["count"]
        if count != 0:
            logging.debug(
                "An entity named %s of type %s exists in the database.",
                entity_name,
                entity_type,
            )
        else:
            logging.debug(
                "No entity named %s of type %s exists in the database.",
                entity_name,
                entity_type,
            )

        return count != 0


def get_entity_id(db_connection, entity_name, entity_type):
    """Return the ID corresponding to the entity with the specified name and type."""
    logging.debug("Looking for entity ID for %s of type %s.", entity_name, entity_type)
    with db_connection.cursor() as cursor:
        logging.debug(
            "Checking to see if any entity named %s of type %s exists in the database.",
            entity_name,
            entity_type,
        )
        cursor.execute(ENTITY_ID_QUERY, (entity_name, entity_type))

        # Note that we are assuming there is only a single match.
        return cursor.fetchone()["entity_id"]


def add_user(
    db_connection: psycopg.Connection,
    username: str,
    password: str = None,
    salt: bytes = None,
) -> int:
    """Add a user, returning its corresponding entity ID.

    If password (salt) is None (the default) then a random password
    (salt) will be generated for the user.

    Note that the salt should be an array of bytes, while the password
    should be an ASCII string.

    """
    logging.debug("Adding user entry.")

    if password is None:
        # Generate a random password consisting of ASCII letters and
        # digits
        alphabet = string.ascii_letters + string.digits
        password = "".join(
            secrets.choice(alphabet) for i in range(DEFAULT_PASSWORD_LENGTH)
        )
    if salt is None:
        # Generate a random byte array
        salt = secrets.token_bytes(DEFAULT_PASSWORD_SALT_LENGTH)

    # Compute the salted password hash that is to be saved to the
    # database.
    #
    # Note that we convert the hexed salt and the salted password hash
    # to uppercase, since that must be done to match the corresponding
    # values in the database that are generated for the default
    # guacadmin password by the database initialization script.
    hexed_salt = salt.hex().upper()
    hasher = hashlib.sha256()
    # We must use the same password hashing algorithm as is used in
    # the Guacamole source code, so we cannot avoid the LGTM warning
    # here.
    hasher.update(password.encode())  # lgtm[py/weak-sensitive-data-hashing]
    hasher.update(hexed_salt.encode())
    salted_password_hash = hasher.hexdigest().upper()

    entity_id = None
    with db_connection.cursor() as cursor:
        cursor.execute(
            INSERT_ENTITY_QUERY,
            (
                username,
                "USER",
            ),
        )
        entity_id = cursor.fetchone()["entity_id"]
        cursor.execute(
            INSERT_USER_QUERY,
            (
                entity_id,
                bytes.fromhex(salted_password_hash),
                salt,
                datetime.datetime.now(),
            ),
        )

    # Commit all pending transactions to the database
    db_connection.commit()

    return entity_id


def instance_connection_exists(db_connection, instance_id):
    """Return a boolean indicating whether a connection for the specified instance exists."""
    with db_connection.cursor() as cursor:
        logging.debug(
            "Checking to see if a connection for the instance ID %s exists in the database.",
            instance_id,
        )
        cursor.execute(
            COUNT_QUERY,
            (
                "instance_id",
                instance_id,
            ),
        )
        count = cursor.fetchone()["count"]
        if count != 0:
            logging.debug(
                "A connection for the instance %s exists in the database.", instance_id
            )
        else:
            logging.debug(
                "No connection for the instance %s exists in the database.", instance_id
            )

        return count != 0


def add_instance_connection(
    db_connection,
    instance,
    connection_parameters: ConnectionParameters,
    entity_id,
):
    """Add a connection for the EC2 instance."""
    logging.debug("Adding connection entry for %s.", instance.id)
    hostname = instance.private_dns_name
    connection_name = get_connection_name(instance)
    is_windows = False
    connection_protocol = "vnc"
    # Note that the Windows VNC server software in use must support a connection
    # to display 1 for this port to work.
    connection_port = 5901
    if instance.platform and instance.platform.lower() == "windows":
        logging.debug(
            "Instance %s is Windows and therefore uses different parameters for VNC.",
            instance.id,
        )
        is_windows = True

    with db_connection.cursor() as cursor:
        cursor.execute(
            INSERT_CONNECTION_QUERY,
            (
                connection_name,
                connection_protocol,
                10,
                10,
                4822,
                "guacd",
                "NONE",
            ),
        )
        connection_id = cursor.fetchone()["connection_id"]

        guac_conn_params = (
            (
                connection_id,
                "cursor",
                "local",
            ),
            (
                connection_id,
                "sftp-directory",
                f"/home/{connection_parameters.vnc_username}/Documents",
            ),
            (
                connection_id,
                "sftp-username",
                connection_parameters.vnc_username,
            ),
            (
                connection_id,
                "sftp-private-key",
                connection_parameters.private_ssh_key,
            ),
            (
                connection_id,
                "sftp-server-alive-interval",
                60,
            ),
            (
                connection_id,
                "sftp-root-directory",
                "/",
            ),
            (
                connection_id,
                "enable-sftp",
                True,
            ),
            (
                connection_id,
                "color-depth",
                24,
            ),
            (
                connection_id,
                "hostname",
                hostname,
            ),
            (
                connection_id,
                "password",
                connection_parameters.vnc_password,
            ),
            (
                connection_id,
                "port",
                connection_port,
            ),
        )
        if is_windows:
            guac_conn_params = (
                (
                    connection_id,
                    "cursor",
                    "local",
                ),
                (
                    connection_id,
                    "sftp-directory",
                    f"{connection_parameters.windows_sftp_base}/Documents",
                ),
                (
                    connection_id,
                    "sftp-username",
                    connection_parameters.rdp_username,
                ),
                (
                    connection_id,
                    "sftp-private-key",
                    connection_parameters.private_ssh_key,
                ),
                (
                    connection_id,
                    "sftp-server-alive-interval",
                    60,
                ),
                # This must be the root of the filesystem to give access to any
                # network drives through Guacamole's file sharing functionality.
                (
                    connection_id,
                    "sftp-root-directory",
                    "/",
                ),
                (
                    connection_id,
                    "enable-sftp",
                    True,
                ),
                (
                    connection_id,
                    "color-depth",
                    24,
                ),
                (
                    connection_id,
                    "hostname",
                    hostname,
                ),
                (
                    connection_id,
                    "password",
                    connection_parameters.vnc_password,
                ),
                (
                    connection_id,
                    "port",
                    connection_port,
                ),
            )

        logging.debug(
            "Adding connection parameter entries for connection named %s.",
            connection_name,
        )
        cursor.executemany(INSERT_CONNECTION_PARAMETER_QUERY, guac_conn_params)

        logging.debug(
            "Adding connection attribute entries for connection named %s.",
            connection_name,
        )
        cursor.execute(
            INSERT_CONNECTION_ATTRIBUTE_QUERY,
            (
                "instance_id",
                instance.id,
            ),
        )

        logging.debug(
            "Adding connection permission entries for connection named %s.",
            connection_name,
        )
        cursor.execute(
            INSERT_CONNECTION_PERMISSION_QUERY,
            (
                entity_id,
                connection_id,
                "READ",
            ),
        )

    # Commit all pending transactions to the database
    db_connection.commit()


def remove_connection(db_connection, connection_id):
    """Remove all connections corresponding to the specified ID."""
    logging.debug("Removing connection entries for %s.", connection_id)
    with db_connection.cursor() as cursor:
        cursor.execute(DELETE_CONNECTIONS_QUERY, (connection_id,))

        logging.debug("Removing connection parameter entries for %s.", connection_id)
        cursor.execute(DELETE_CONNECTION_PARAMETERS_QUERY, (connection_id,))

        logging.debug("Removing connection attribute entries for %s.", connection_id)
        cursor.execute(DELETE_CONNECTION_ATTRIBUTES_QUERY, (connection_id,))

        logging.debug("Removing connection permission entries for %s.", connection_id)
        cursor.execute(DELETE_CONNECTION_PERMISSIONS_QUERY, (connection_id,))


def remove_instance_connections(db_connection, instance):
    """Remove all connections corresponding to the EC2 instance."""
    instance_id = instance.id
    logging.debug("Removing connections for %s.", instance_id)
    with db_connection.cursor() as cursor:
        logging.debug(
            "Checking to see if any connections for instance %s exist in the database.",
            instance_id,
        )
        cursor.execute(
            IDS_QUERY,
            (
                "instance_id",
                instance_id,
            ),
        )
        for record in cursor:
            logging.info("Removing entries for instance %s.", instance_id)
            connection_id = record["connection_id"]
            remove_connection(db_connection, connection_id)

    # Commit all pending transactions to the database
    db_connection.commit()


def get_connection_name(instance):
    """Return the unique connection name for an EC2 instance."""
    name = [tag["Value"] for tag in instance.tags if tag["Key"] == "Name"][0]
    private_ip = instance.private_ip_address
    public_ip = instance.public_ip_address
    ipv6_ip = instance.ipv6_address

    ips = "/".join([ip for ip in (private_ip, public_ip, ipv6_ip) if ip])
    return " - ".join([s for s in (f"{name} ({instance.id})", ips) if s])


def process_instance(
    db_connection,
    instance,
    add_instance_states,
    remove_instance_states,
    connection_parameters: ConnectionParameters,
    entity_id,
):
    """Add/remove connections for the specified EC2 instance."""
    instance_id = instance.id
    logging.debug("Examining instance %s.", instance_id)
    state = instance.state["Name"]
    if state in add_instance_states:
        logging.info(
            "Instance %s is in state %s and will be added if not already present.",
            instance_id,
            state,
        )
        if not instance_connection_exists(db_connection, instance_id):
            logging.info("Adding a connection for %s.", instance_id)
            add_instance_connection(
                db_connection,
                instance,
                connection_parameters,
                entity_id,
            )
        else:
            logging.debug(
                "Connection for %s already exists in the database.", instance_id
            )
    elif state in remove_instance_states:
        logging.info(
            "Instance %s is in state %s and will be removed if present.",
            instance_id,
            state,
        )
        remove_instance_connections(db_connection, instance)
    else:
        logging.debug(
            "Instance %s is in state %s and WILL NOT be added or removed.",
            instance_id,
            state,
        )


def check_for_ghost_instances(db_connection, instances):
    """Check to see if any connections belonging to nonexistent instances are in the database."""
    instance_ids = [instance.id for instance in instances]
    with db_connection.cursor() as cursor:
        cursor.execute(ALL_IDS_QUERY, "instance_id")
        for record in cursor:
            connection_id = record["connection_id"]
            instance_id = record["attribute_value"]
            if instance_id not in instance_ids:
                logging.info(
                    "Connection for %s being removed since that instance no longer exists.",
                    instance_id,
                )
                remove_connection(db_connection, connection_id)

    db_connection.commit()


def main() -> None:
    """Add/remove connections to Guacamole DB as necessary."""
    # Parse command line arguments
    args = docopt.docopt(__doc__, version=__version__)
    # Validate and convert arguments as needed
    schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            "--sleep": And(
                Use(float),
                error="Value for --sleep must be parseable as a floating point number.",
            ),
            Optional("--vpc-id"): Or(
                None,
                And(
                    str,
                    Use(str.lower),
                    lambda x: VPC_ID_REGEX.match(x) is not None,
                    error="Possible values for --vpc-id are the characters vpc- followed by either 8 or 17 hexadecimal digits.",
                ),
            ),
            str: object,  # Don't care about other keys, if any
        }
    )
    try:
        validated_args = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Set up logging
    log_level = validated_args["--log-level"]
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
    )

    add_instance_states = DEFAULT_ADD_INSTANCE_STATES
    postgres_db_name = DEFAULT_POSTGRES_DB_NAME
    postgres_hostname = DEFAULT_POSTGRES_HOSTNAME
    postgres_port = DEFAULT_POSTGRES_PORT
    remove_instance_states = DEFAULT_REMOVE_INSTANCE_STATES

    oneshot = validated_args["--oneshot"]
    logging.debug("oneshot is %s.", oneshot)

    postgres_password = validated_args["--postgres-password"]
    if postgres_password is None:
        with open(validated_args["--postgres-password-file"], "r") as file:
            postgres_password = file.read()

    postgres_username = validated_args["--postgres-username"]
    if postgres_username is None:
        with open(validated_args["--postgres-username-file"], "r") as file:
            postgres_username = file.read()

    rdp_password = validated_args["--rdp-password"]
    if rdp_password is None:
        with open(validated_args["--rdp-password-file"], "r") as file:
            rdp_password = file.read()

    rdp_username = validated_args["--rdp-username"]
    if rdp_username is None:
        with open(validated_args["--rdp-username-file"], "r") as file:
            rdp_username = file.read()

    vnc_password = validated_args["--vnc-password"]
    if vnc_password is None:
        with open(validated_args["--vnc-password-file"], "r") as file:
            vnc_password = file.read()

    vnc_username = validated_args["--vnc-username"]
    if vnc_username is None:
        with open(validated_args["--vnc-username-file"], "r") as file:
            vnc_username = file.read()

    private_ssh_key = validated_args["--private-ssh-key"]
    if private_ssh_key is None:
        with open(validated_args["--private-ssh-key-file"], "r") as file:
            private_ssh_key = file.read()

    windows_sftp_base = validated_args["--windows-sftp-base"]
    if windows_sftp_base is None:
        with open(validated_args["--windows-sftp-base-file"], "r") as file:
            windows_sftp_base = file.read()

    db_connection_string = f"user={postgres_username} password={postgres_password} host={postgres_hostname} port={postgres_port} dbname={postgres_db_name}"

    vpc_id = validated_args["--vpc-id"]
    # TODO: Verify that the region specified is indeed a valid AWS
    # region.  See cisagov/guacscanner#6 for more details.
    region = validated_args["--region"]

    # If no VPC ID was specified on the command line then grab the VPC
    # ID where this instance resides and use that.
    ec2 = None
    if vpc_id is None:
        instance_id = ec2_metadata.instance_id
        region = ec2_metadata.region
        ec2 = boto3.resource("ec2", region_name=region)
        instance = ec2.Instance(instance_id)
        vpc_id = instance.vpc_id
    else:
        ec2 = boto3.resource("ec2", region_name=region)

    logging.info("Examining instances in VPC %s.", vpc_id)

    instances = ec2.Vpc(vpc_id).instances.all()
    keep_looping = True
    guacuser_id = None
    while keep_looping:
        time.sleep(validated_args["--sleep"])

        try:
            db_connection = psycopg.connect(
                db_connection_string, row_factory=psycopg.rows.dict_row
            )
        except psycopg.OperationalError:
            logging.exception(
                "Unable to connect to the PostgreSQL database backending Guacamole."
            )
            continue

        # Create guacuser if it doesn't already exist
        #
        # TODO: Figure out a way to make this cleaner.  We don't want
        # to hardcode the guacuser name, and we want to allow the user
        # to specify a list of users that should be created if they
        # don't exist and given access to use the connections created
        # by guacscanner.  See cisagov/guacscanner#4 for more details.
        if guacuser_id is None:
            # We haven't initialized guacuser_id yet, so let's do it
            # now.
            if not entity_exists(db_connection, "guacuser", "USER"):
                guacuser_id = add_user(db_connection, "guacuser")
            else:
                guacuser_id = get_entity_id(db_connection, "guacuser", "USER")

        for instance in instances:
            ami = ec2.Image(instance.image_id)
            # Early exit if this instance is running an AMI that we
            # want to avoid adding to Guacamole.
            try:
                ami_matches = [
                    regex.match(ami.name) for regex in DEFAULT_AMI_SKIP_REGEXES
                ]
            except AttributeError:
                # This exception can be thrown when an instance is
                # running an AMI to which the account no longer has
                # access; for example, between the time when a new AMI
                # of the same type is built and terraform-post-packer
                # is run and the new AMI is applied to the account.
                # In this situation we can't take any action because
                # we can't access the AMI's name and hence can't know
                # if the instance AMI is of a type whose Guacamole
                # connections are being controlled by guacscanner.
                #
                # In any event, this continue statement should keep
                # things moving when it does.
                logging.exception(
                    "Unable to determine if instance is running an AMI that would cause it to be skipped."
                )
                continue
            if any(ami_matches):
                continue

            process_instance(
                db_connection,
                instance,
                add_instance_states,
                remove_instance_states,
                ConnectionParameters(
                    private_ssh_key=private_ssh_key,
                    rdp_password=rdp_password,
                    rdp_username=rdp_username,
                    vnc_password=vnc_password,
                    vnc_username=vnc_username,
                    windows_sftp_base=windows_sftp_base,
                ),
                guacuser_id,
            )

        logging.info(
            "Checking to see if any connections belonging to nonexistent instances are in the database."
        )
        check_for_ghost_instances(db_connection, instances)

        if oneshot:
            logging.debug(
                "Stopping Guacamole connection update loop because --oneshot is present."
            )
            keep_looping = False

        # pycopg.connect() can act as a context manager, but the
        # connection is not closed when you leave the context;
        # therefore, we still have to close the connection manually.
        db_connection.close()

    logging.shutdown()

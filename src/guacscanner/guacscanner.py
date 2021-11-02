"""Query AWS for new (destroyed) instances and add (remove) Guacamole connections for them.

Also check for instances that have been destroyed and remove their
corresponding connections.

EXIT STATUS
  0   Update was successful.
  >0  An error occurred.

Usage:
  guacscanner [--log-level=LEVEL] [--postgres-password=PASSWORD] [--postgres-password-file=FILENAME] [--private-ssh-key=KEY] [--private-ssh-key-file=FILENAME] [--postgres-username=USERNAME] [--postgres-username-file=FILENAME] [--vnc-password=PASSWORD] [--vnc-password-file=FILENAME] [--vnc-username=USERNAME] [--vnc-username-file=FILENAME] [--vpc-id=VPC_ID]
  guacscanner (-h | --help)

Options:
  -h --help              Show this message.
  --log-level=LEVEL      If specified, then the log level will be set to
                         the specified value.  Valid values are "debug", "info",
                         "warning", "error", and "critical". [default: info]
  --postgres-password=PASSWORD    If specified then the specified value will be used as the password when connecting to the PostgreSQL database.  Otherwise, the password will be read from a local file.
  --postgres-password-file=FILENAME    The file from which the PostgreSQL password will be read. [default: /run/secrets/postgres-password]
  --postgres-username=USERNAME    If specified then the specified value will be used when connecting to the PostgreSQL database.  Otherwise, the username will be read from a local file.
  --postgres-username-file=FILENAME    The file from which the PostgreSQL username will be read. [default: /run/secrets/postgres-username]
  --private-ssh-key=KEY  If specified then the specified value will be used for the private ssh key.  Otherwise, the ssh key will be read from a local file.
  --private-ssh-key-file=FILENAME  The file from which the private ssh key will be read. [default: /run/secrets/private-ssh-key]
  --vnc-password=PASSWORD  If specified then the specified value will be used for the VNC password.  Otherwise, the password will be read from a local file.
  --vnc-password-file=FILENAME  The file from which the VNC password will be read. [default: /run/secrets/vnc-password]
  --vnc-username=USERNAME  If specified then the specified value will be used for the VNC username.  Otherwise, the username will be read from a local file.
  --vnc-username-file=FILENAME  The file from which the VNC username will be read. [default: /run/secrets/vnc-username]
  --vpc-id=VPC_ID        If specified then query for EC2 instances created
                         or destroyed in the specified VPC ID.  If not
                         specified then the ID of the VPC in which the host
                         resides will be used.
"""


# Standard Python Libraries
import logging
import re
import sys

# Third-Party Libraries
import boto3
import docopt
from ec2_metadata import ec2_metadata
import psycopg
from psycopg import sql
from schema import And, Schema, SchemaError, Use

from ._version import __version__

DEFAULT_ADD_INSTANCE_STATES = [
    "running",
]
DEFAULT_POSTGRES_DB_NAME = "guacamole_db"
DEFAULT_POSTGRES_HOSTNAME = "postgres"
DEFAULT_POSTGRES_PORT = 5432
DEFAULT_REMOVE_INSTANCE_STATES = [
    "terminated",
]
COUNT_QUERY = sql.SQL(
    "SELECT COUNT({id_field}) FROM {table} WHERE {name_field} = %s"
).format(
    id_field=sql.Identifier("connection_id"),
    table=sql.Identifier("guacamole_connection"),
    name_field=sql.Identifier("connection_name"),
)
IDS_QUERY = sql.SQL("SELECT {id_field} FROM {table} WHERE {name_field} = %s").format(
    id_field=sql.Identifier("connection_id"),
    table=sql.Identifier("guacamole_connection"),
    name_field=sql.Identifier("connection_name"),
)
NAMES_QUERY = sql.SQL("SELECT {id_field}, {name_field} FROM {table}").format(
    id_field=sql.Identifier("connection_id"),
    name_field=sql.Identifier("connection_name"),
    table=sql.Identifier("guacamole_connection"),
)
INSERT_CONNECTION_QUERY = sql.SQL(
    """INSERT INTO {table} (
    {name_field}, {protocol_field}, {max_connections_field},
    {max_connections_per_user_field}, {proxy_port_field}, {proxy_hostname_field},
    {proxy_encryption_method_field})
    VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;"""
).format(
    table=sql.Identifier("guacamole_connection"),
    name_field=sql.Identifier("connection_name"),
    protocol_field=sql.Identifier("protocol"),
    max_connections_field=sql.Identifier("max_connections"),
    max_connections_per_user_field=sql.Identifier("max_connections_per_user"),
    proxy_port_field=sql.Identifier("proxy_port"),
    proxy_hostname_field=sql.Identifier("proxy_hostname"),
    proxy_encryption_method_field=sql.Identifier("proxy_encryption_method"),
)
INSERT_CONNECTION_PARAMETER_QUERY = sql.SQL(
    """INSERT INTO {table}
    ({id_field}, {parameter_name_field}, {parameter_value_field})
    VALUES (%s, %s, %s);"""
).format(
    table=sql.Identifier("guacamole_connection_parameter"),
    id_field=sql.Identifier("connection_id"),
    parameter_name_field=sql.Identifier("parameter_name"),
    parameter_value_field=sql.Identifier("parameter_value"),
)
DELETE_CONNECTIONS_QUERY = sql.SQL(
    """DELETE FROM {table} WHERE {id_field} = %s;"""
).format(table=sql.Identifier("guacamole_connection"), id_field=sql.Identifier("id"))
DELETE_CONNECTION_PARAMETERS_QUERY = sql.SQL(
    """DELETE FROM {table} WHERE {id_field} = %s;"""
).format(
    table=sql.Identifier("guacamole_connection_parameter"),
    id_field=sql.Identifier("id"),
)


def instance_connection_exists(db_connection, connection_name):
    """Return a boolean indicating whether a connection with the specified name exists."""
    with db_connection.cursor() as cursor:
        logging.debug(
            "Checking to see if a connection named %s exists in the database.",
            connection_name,
        )
        cursor.execute(COUNT_QUERY, (connection_name,))
        count = cursor.fetchone()["count"] != 0
        if count != 0:
            logging.debug(
                "A connection named %s exists in the database.", connection_name
            )
        else:
            logging.debug(
                "No connection named %s exists in the database.", connection_name
            )

        return count != 0


def add_instance_connection(
    db_connection, instance, vnc_username, vnc_password, private_ssh_key
):
    """Add a connection for the EC2 instance."""
    logging.debug("Adding connection entry for %s.", instance.id)
    hostname = instance.private_dns_name
    connection_name = get_connection_name(instance)
    with db_connection.cursor() as cursor:
        cursor.execute(
            INSERT_CONNECTION_QUERY,
            (
                connection_name,
                "vnc",
                10,
                10,
                4822,
                "guacd",
                "NONE",
            ),
        )
        connection_id = cursor.fetchone()["id"]

        logging.debug(
            "Adding connection parameter entries for connection named %s.",
            connection_name,
        )
        cursor.executemany(
            INSERT_CONNECTION_PARAMETER_QUERY,
            (
                (
                    connection_id,
                    "cursor",
                    "local",
                ),
                (
                    connection_id,
                    "sftp-directory",
                    f"/home/{vnc_username}/Documents",
                ),
                (
                    connection_id,
                    "sftp-username",
                    vnc_username,
                ),
                (
                    connection_id,
                    "sftp-private-key",
                    private_ssh_key,
                ),
                (
                    connection_id,
                    "sftp-server-alive-interval",
                    60,
                ),
                (
                    connection_id,
                    "sftp-root-directory",
                    f"/home/{vnc_username}/",
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
                    vnc_password,
                ),
                (
                    connection_id,
                    "port",
                    5901,
                ),
            ),
        )

    # Commit all pending transactions to the database
    db_connection.commit()


def remove_instance_connections(db_connection, instance):
    """Remove all connections corresponding to the EC2 isntance."""
    logging.debug("Removing connections for %s.", instance.id)
    connection_name = get_connection_name(instance)
    with db_connection.cursor() as cursor:
        logging.debug(
            "Checking to see if any connections named %s exist in the database.",
            connection_name,
        )
        cursor.execute(IDS_QUERY, (connection_name,))
        for record in cursor:
            logging.info("Removing entries for connections named %s.", connection_name)
            connection_id = record["connection_id"]
            logging.debug("Removing connection entries for %s.", connection_id)
            cursor.execute(DELETE_CONNECTIONS_QUERY, (connection_id,))

            logging.debug(
                "Removing connection parameter entries for %s.", connection_id
            )
            cursor.execute(DELETE_CONNECTION_PARAMETERS_QUERY, (connection_id,))

    # Commit all pending transactions to the database
    db_connection.commit()


def get_connection_name(instance):
    """Return the unique connection name for an EC2 instance."""
    return f"{instance.private_dns_name} ({instance.id})"


def process_instance(
    db_connection,
    instance,
    add_instance_states,
    remove_instance_states,
    vnc_username,
    vnc_password,
    private_ssh_key,
):
    """Add/remove connections for the specified EC2 instance."""
    logging.debug("Examining instance %s.", instance.id)
    state = instance.state.name
    connection_name = get_connection_name(instance)
    logging.debug("Connection name is %s.", connection_name)
    if state in add_instance_states:
        logging.info(
            "Instance %s is in state %s and will be added if not already present.",
            instance.id,
            state,
        )
        if not instance_connection_exists(db_connection, connection_name):
            logging.info("Adding a connection for %s.", instance.id)
            add_instance_connection(
                db_connection, instance, vnc_username, vnc_password, private_ssh_key
            )
        else:
            logging.debug(
                "Connection for %s already exists in the database.", instance.id
            )
    elif state in remove_instance_states:
        logging.info(
            "Instance %s is in state %s and will be removed if present.",
            instance.id,
            state,
        )
        remove_instance_connections(db_connection, instance)
    else:
        logging.debug(
            "Instance %s is in state %s and WILL NOT be added or removed.",
            instance.id,
            state,
        )


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
            "--vpc-id": And(
                str,
                Use(str.lower),
                lambda x: re.fullmatch(r"^vpc-[0-9a-f]{17}$", x) is not None,
                error="Possible values for --vpc-id are the characters vpc- followed by 17 hexadecimal digits.",
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

    postgres_password = None
    if "--postgres-password" in validated_args:
        postgres_password = validated_args["--postgres-password"]
    else:
        with open(validated_args["--postgres-password-file"], "r") as file:
            postgres_password = file.read()

    postgres_username = None
    if "--postgres-username" in validated_args:
        postgres_username = validated_args["--postgres-username"]
    else:
        with open(validated_args["--postgres-username-file"], "r") as file:
            postgres_username = file.read()

    vnc_password = None
    if "--vnc-password" in validated_args:
        vnc_password = validated_args["--vnc-password"]
    else:
        with open(validated_args["--vnc-password-file"], "r") as file:
            vnc_password = file.read()

    vnc_username = None
    if "--vnc-username" in validated_args:
        vnc_username = validated_args["--vnc-username"]
    else:
        with open(validated_args["--vnc-username-file"], "r") as file:
            vnc_username = file.read()

    private_ssh_key = None
    if "--private-ssh-key" in validated_args:
        private_ssh_key = validated_args["--private-ssh-key"]
    else:
        with open(validated_args["--private-ssh-key-file"], "r") as file:
            private_ssh_key = file.read()

    db_connection_string = f"postgresql://{postgres_username}:{postgres_password}@{postgres_hostname}:{postgres_port}/{postgres_db_name}"

    vpc_id = None
    if "--vpc-id" in validated_args:
        vpc_id = validated_args["--vpc-id"]
    else:
        vpc_id = ec2_metadata.vpc_id
    logging.info("Examining instances in VPC %s.", vpc_id)

    ec2 = boto3.resource("ec2", region_name="us-east-1")

    with psycopg.connect(db_connection_string) as db_connection:
        for instance in ec2.Vpc(vpc_id).instances.all():
            process_instance(
                db_connection,
                instance,
                add_instance_states,
                remove_instance_states,
                vnc_username,
                vnc_password,
                private_ssh_key,
            )

        # logging.debug(
        #     "Checking to see if any connections belonging to nonexistent instances are in the database."
        # )
        # cursor.execute(NAMES_QUERY)
        # for record in cursor:
        #     connection_id = record["connection_id"]
        #     connection_name = record["connection_name"]
        #     m = re.match(r"^.* \((?P<id>i-\d{17})\)$", connection_name)
        #     instance_id = None
        #     if m:
        #         instance_id = m.group("id")
        #     ec2.Instance(instance_id)

    logging.shutdown()

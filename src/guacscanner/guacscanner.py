"""Query AWS for new (destroyed) instances and add (remove) Guacamole connections for them.

Also check for instances that have been destroyed and remove their
corresponding connections.

EXIT STATUS
  0   Update was successful.
  >0  An error occurred.

Usage:
  guacscanner [--log-level=LEVEL] [--oneshot] [--sleep=SECONDS] [--postgres-password=PASSWORD|--postgres-password-file=FILENAME] [--private-ssh-key=KEY|--private-ssh-key-file=FILENAME] [--postgres-username=USERNAME|--postgres-username-file=FILENAME] [--rdp-password=PASSWORD|--rdp-password-file=FILENAME] [--rdp-username=USERNAME|--rdp-username-file=FILENAME] [--vnc-password=PASSWORD|--vnc-password-file=FILENAME] [--vnc-username=USERNAME|--vnc-username-file=FILENAME] [--vpc-id=VPC_ID]
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
  --private-ssh-key=KEY  If specified then the specified value will be used for the private ssh key.  Otherwise, the ssh key will be read from a local file.
  --private-ssh-key-file=FILENAME  The file from which the private ssh key will be read. [default: /run/secrets/private-ssh-key]
  --rdp-password=PASSWORD  If specified then the specified value will be used for the RDP password.  Otherwise, the password will be read from a local file.
  --rdp-password-file=FILENAME  The file from which the RDP password will be read. [default: /run/secrets/rdp-password]
  --rdp-username=USERNAME  If specified then the specified value will be used for the RDP username.  Otherwise, the username will be read from a local file.
  --rdp-username-file=FILENAME  The file from which the RDP username will be read. [default: /run/secrets/rdp-username]
  --sleep=SECONDS  Sleep for the specified number of seconds between executions of the Guacamole connection update loop. [default: 60]
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
import datetime
import logging
import re
import sys
import time

# Third-Party Libraries
import boto3
import docopt
from ec2_metadata import ec2_metadata
import psycopg
from psycopg import sql
from schema import And, Optional, Or, Schema, SchemaError, Use

from ._version import __version__

# TODO: Create command line options with defaults for these variables.
# See cisagov/guacscanner#2 for more details.
DEFAULT_ADD_INSTANCE_STATES = [
    "running",
]
DEFAULT_POSTGRES_DB_NAME = "guacamole_db"
DEFAULT_POSTGRES_HOSTNAME = "postgres"
DEFAULT_POSTGRES_PORT = 5432
DEFAULT_REMOVE_INSTANCE_STATES = [
    "terminated",
]
DEFAULT_AMI_SKIP_REGEXES = [
    re.compile(r"^guacamole-.*$"),
    re.compile(r"^samba-.*$"),
]

# Some precompiled regexes
INSTANCE_ID_REGEX = re.compile(r"^.* \((?P<id>i-[0-9a-f]{17})\)$")
VPC_ID_REGEX = re.compile(r"^vpc-([0-9a-f]{8}|[0-9a-f]{17})$")

# TODO: Determine if we can use f-strings instead of .format() for
# these queries.  Also define the sql.Identifier() variables
# separately so that they can be reused where that is possible.  See
# cisagov/guacscanner#3 for more details.

# The PostgreSQL queries used for adding and removing connections
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
    VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING {id_field};"""
).format(
    table=sql.Identifier("guacamole_connection"),
    name_field=sql.Identifier("connection_name"),
    protocol_field=sql.Identifier("protocol"),
    max_connections_field=sql.Identifier("max_connections"),
    max_connections_per_user_field=sql.Identifier("max_connections_per_user"),
    proxy_port_field=sql.Identifier("proxy_port"),
    proxy_hostname_field=sql.Identifier("proxy_hostname"),
    proxy_encryption_method_field=sql.Identifier("proxy_encryption_method"),
    id_field=sql.Identifier("connection_id"),
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
).format(
    table=sql.Identifier("guacamole_connection"),
    id_field=sql.Identifier("connection_id"),
)
DELETE_CONNECTION_PARAMETERS_QUERY = sql.SQL(
    """DELETE FROM {table} WHERE {id_field} = %s;"""
).format(
    table=sql.Identifier("guacamole_connection_parameter"),
    id_field=sql.Identifier("connection_id"),
)

# The PostgreSQL queries used for adding and removing users
ENTITY_COUNT_QUERY = sql.SQL(
    "SELECT COUNT({id_field}) FROM {table} WHERE {name_field} = %s AND {type_field} = %s"
).format(
    id_field=sql.Identifier("entity_id"),
    table=sql.Identifier("guacamole_entity"),
    name_field=sql.Identifier("name"),
    type_field=sql.Identifier("type"),
)
ENTITY_ID_QUERY = sql.SQL(
    "SELECT {id_field} FROM {table} WHERE {name_field} = %s AND {type_field} = %s"
).format(
    id_field=sql.Identifier("entity_id"),
    table=sql.Identifier("guacamole_entity"),
    name_field=sql.Identifier("name"),
    type_field=sql.Identifier("type"),
)
INSERT_ENTITY_QUERY = sql.SQL(
    """INSERT INTO {table} (
    {name_field}, {type_field})
    VALUES (%s, %s) RETURNING {id_field};"""
).format(
    table=sql.Identifier("guacamole_entity"),
    name_field=sql.Identifier("name"),
    type_field=sql.Identifier("type"),
    id_field=sql.Identifier("entity_id"),
)
INSERT_USER_QUERY = sql.SQL(
    """INSERT INTO {table} (
    {id_field}, {hash_field}, {salt_field}, {date_field})
    VALUES (%s, %s, %s, %s);"""
).format(
    table=sql.Identifier("guacamole_user"),
    id_field=sql.Identifier("entity_id"),
    hash_field=sql.Identifier("password_hash"),
    salt_field=sql.Identifier("password_salt"),
    date_field=sql.Identifier("password_date"),
)
# The PostgreSQL queries used to add and remove connection
# permissions
INSERT_CONNECTION_PERMISSION_QUERY = sql.SQL(
    """INSERT INTO {table} (
    {entity_id_field}, {connection_id_field}, {permission_field})
    VALUES (%s, %s, %s);"""
).format(
    table=sql.Identifier("guacamole_connection_permission"),
    entity_id_field=sql.Identifier("entity_id"),
    connection_id_field=sql.Identifier("connection_id"),
    permission_field=sql.Identifier("permission"),
)
DELETE_CONNECTION_PERMISSIONS_QUERY = sql.SQL(
    """DELETE FROM {table} WHERE {connection_id_field} = %s;"""
).format(
    table=sql.Identifier("guacamole_connection_permission"),
    connection_id_field=sql.Identifier("connection_id"),
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


def add_user(db_connection, username):
    """Add a user, returning its corresponding entity ID."""
    logging.debug("Adding user entry for %s.", username)
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
                # guacadmin
                bytes.fromhex(
                    "CA458A7D494E3BE824F5E1E175A1556C0F8EEF2C2D7DF3633BEC4A29C4411960"
                ),
                bytes.fromhex(
                    "FE24ADC5E11E2B25288D1704ABE67A79E342ECC26064CE69C5B3177795A82264"
                ),
                datetime.datetime.now(),
            ),
        )

    # Commit all pending transactions to the database
    db_connection.commit()

    return entity_id


def instance_connection_exists(db_connection, connection_name):
    """Return a boolean indicating whether a connection with the specified name exists."""
    with db_connection.cursor() as cursor:
        logging.debug(
            "Checking to see if a connection named %s exists in the database.",
            connection_name,
        )
        cursor.execute(COUNT_QUERY, (connection_name,))
        count = cursor.fetchone()["count"]
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
    db_connection,
    instance,
    vnc_username,
    vnc_password,
    private_ssh_key,
    rdp_username,
    rdp_password,
    entity_id,
):
    """Add a connection for the EC2 instance."""
    logging.debug("Adding connection entry for %s.", instance.id)
    hostname = instance.private_dns_name
    connection_name = get_connection_name(instance)
    is_windows = False
    connection_protocol = "vnc"
    connection_port = 5901
    if instance.platform and instance.platform.lower() == "windows":
        logging.debug("Instance %s is Windows and therefore uses RDP.", instance.id)
        is_windows = True
        connection_protocol = "rdp"
        connection_port = 3389

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
                connection_port,
            ),
        )
        if is_windows:
            guac_conn_params = (
                (
                    connection_id,
                    "ignore-cert",
                    True,
                ),
                (
                    connection_id,
                    "hostname",
                    hostname,
                ),
                (
                    connection_id,
                    "password",
                    rdp_password,
                ),
                (
                    connection_id,
                    "port",
                    connection_port,
                ),
                (
                    connection_id,
                    "username",
                    rdp_username,
                ),
            )

        logging.debug(
            "Adding connection parameter entries for connection named %s.",
            connection_name,
        )
        cursor.executemany(INSERT_CONNECTION_PARAMETER_QUERY, guac_conn_params)

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

        logging.debug("Removing connection permission entries for %s.", connection_id)
        cursor.execute(DELETE_CONNECTION_PERMISSIONS_QUERY, (connection_id,))


def remove_instance_connections(db_connection, instance):
    """Remove all connections corresponding to the EC2 instance."""
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
            remove_connection(db_connection, connection_id)

    # Commit all pending transactions to the database
    db_connection.commit()


def get_connection_name(instance):
    """Return the unique connection name for an EC2 instance."""
    name = [tag["Value"] for tag in instance.tags if tag["Key"] == "Name"][0]
    return f"{name} ({instance.id})"


def process_instance(
    db_connection,
    instance,
    add_instance_states,
    remove_instance_states,
    vnc_username,
    vnc_password,
    private_ssh_key,
    rdp_username,
    rdp_password,
    entity_id,
):
    """Add/remove connections for the specified EC2 instance."""
    logging.debug("Examining instance %s.", instance.id)
    state = instance.state["Name"]
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
                db_connection,
                instance,
                vnc_username,
                vnc_password,
                private_ssh_key,
                rdp_username,
                rdp_password,
                entity_id,
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


def check_for_ghost_instances(db_connection, instances):
    """Check to see if any connections belonging to nonexistent instances are in the database."""
    instance_ids = [instance.id for instance in instances]
    with db_connection.cursor() as cursor:
        cursor.execute(NAMES_QUERY)
        for record in cursor:
            connection_id = record["connection_id"]
            connection_name = record["connection_name"]
            m = INSTANCE_ID_REGEX.match(connection_name)
            instance_id = None
            if m:
                instance_id = m.group("id")
            else:
                logging.error(
                    'Connection name "%s" does not contain a valid instance ID',
                    connection_name,
                )

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

    db_connection_string = f"user={postgres_username} password={postgres_password} host={postgres_hostname} port={postgres_port} dbname={postgres_db_name}"
    logging.debug("DB connection string is %s.", db_connection_string)

    vpc_id = validated_args["--vpc-id"]

    ec2 = boto3.resource("ec2", region_name="us-east-1")

    # If no VPC ID was specified on the command line then grab the VPC
    # ID where this instance resides and use that.
    if vpc_id is None:
        instance_id = ec2_metadata.instance_id
        instance = ec2.Instance(instance_id)
        vpc_id = instance.vpc_id
    logging.info("Examining instances in VPC %s.", vpc_id)

    instances = ec2.Vpc(vpc_id).instances.all()
    keep_looping = True
    guacuser_id = None
    while keep_looping:
        try:
            with psycopg.connect(
                db_connection_string, row_factory=psycopg.rows.dict_row
            ) as db_connection:
                # Create guacuser if it doesn't already exist
                #
                # TODO: Figure out a way to make this cleaner.  We
                # don't want to hardcode the guacuser name, and we
                # want to allow the user to specify a list of users
                # that should be created if they don't exist and given
                # access to use the connections created by
                # guacscanner.  See cisagov/guacscanner#4 for more
                # details.
                if guacuser_id is None:
                    # We haven't initialized guacuser_id yet, so let's
                    # do it now.
                    if not entity_exists(db_connection, "guacuser", "USER"):
                        guacuser_id = add_user(db_connection, "guacuser")
                    else:
                        guacuser_id = get_entity_id(db_connection, "guacuser", "USER")

                for instance in instances:
                    ami = ec2.Image(instance.image_id)
                    # Early exit if this instance is running an AMI
                    # that we want to avoid adding to Guacamole.
                    if any(
                        [regex.match(ami.name) for regex in DEFAULT_AMI_SKIP_REGEXES]
                    ):
                        continue

                    process_instance(
                        db_connection,
                        instance,
                        add_instance_states,
                        remove_instance_states,
                        vnc_username,
                        vnc_password,
                        private_ssh_key,
                        rdp_username,
                        rdp_password,
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
                    continue
        except psycopg.OperationalError:
            logging.exception(
                "Unable to connect to the PostgreSQL database backending Guacamole."
            )

        time.sleep(validated_args["--sleep"])

    logging.shutdown()

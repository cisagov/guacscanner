"""pytest plugin configuration.

https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins
"""

# Standard Python Libraries
import itertools
import math
import os
from pathlib import Path
import random
import string
import sys

# Third-Party Libraries
import boto3
from moto import mock_aws
import pytest
from python_on_whales import DockerClient

# Maximum length for PostgreSQL passwords
PASSWORD_MAX_LENGTH = 100

# Some special character sequences that we want to inject into our
# PostgreSQL password to see if our code handles them.
SPECIAL_CHAR_SEQUENCES = ["\\n", "\\r", "\\t", "\\\\", "  "]


@pytest.fixture(autouse=True, scope="session")
def aws_credentials():
    """Create dummy AWS credentials for moto.

    Making this an autouse fixture guarantees that boto3 never sees
    any real credentials that may exist locally.  This guarantees
    that no real API calls are ever made to AWS.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"  # nosec B105
    os.environ["AWS_SECURITY_TOKEN"] = "testing"  # nosec B105
    os.environ["AWS_SESSION_TOKEN"] = "testing"  # nosec B105
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def moto(aws_credentials):
    """Manually create a moto mock.

    Doing this instead of using the @mock_aws decorator allows us to
    control the scope.
    """
    mock = mock_aws()
    mock.start()
    yield mock
    mock.stop()


@pytest.fixture
def ec2(moto):
    """Mock EC2 boto3 client."""
    return boto3.client("ec2", "us-east-1")


@pytest.fixture
def vpc_cidr():
    """Create a random /24 CIDR block inside of 10.0.0.0/8."""
    # The following lines generate warnings from bandit (B311) and
    # flake8 (DUO102) about "Standard pseudo-random generators are not
    # suitable for security/cryptographic purposes." and "insecure use
    # of "random" module, prefer "random.SystemRandom", respectively.
    # We aren't using Random() for the purposes of cryptography here, so
    # we can safely ignore these warnings.
    return (
        f"10.{random.randrange(1, 254)}."  # noqa: DUO102 # nosec B311
        f"{random.randrange(1, 254)}.0/24"  # noqa: DUO102 # nosec B311
    )


@pytest.fixture
def vpc_id(ec2, vpc_cidr):
    """Create a VPC and return the VPC ID."""
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr)
    return vpc["Vpc"]["VpcId"]


@pytest.fixture
def subnet_id(ec2, vpc_cidr, vpc_id):
    """Create a single subnet that takes up the entire VPC and return the subnet ID."""
    subnet = ec2.create_subnet(CidrBlock=vpc_cidr, VpcId=vpc_id)
    return subnet["Subnet"]["SubnetId"]


@pytest.fixture(
    # Associate a nice name with each param value
    ids=lambda x: f"{x[0]} {'with' if x[1] else 'without'} public IP",
    # Returns the Cartesian product as a list of tuples
    params=itertools.product(["Linux", "Windows"], [True, False]),
)
def instance(ec2, request, subnet_id):
    """Create an instance running the specified OS."""
    os = request.param[0]
    if os.lower() == "linux":
        ami = "amzn-ami-hvm-2017.09.1.20171103-x86_64-gp2"
    elif os.lower() == "windows":
        ami = "Windows_Server-2016-English-Full-SQL_2017_Enterprise-2017.10.13"
    else:
        raise ValueError(f"{os} is not a valid value for the instance OS.")

    assign_public_ip = request.param[1]

    amis = ec2.describe_images(
        Filters=[
            {
                "Name": "Name",
                "Values": [ami],
            }
        ]
    )
    ami = amis["Images"][0]
    ami_id = ami["ImageId"]

    response = ec2.run_instances(
        ImageId=ami_id,
        MaxCount=1,
        MinCount=1,
        NetworkInterfaces=[
            {
                "AssociatePublicIpAddress": assign_public_ip,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
            }
        ],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": os.capitalize()}],
            }
        ],
    )

    instance = response["Instances"][0]
    return {
        "id": instance["InstanceId"],
        "os": os,
        "private_ip": instance["PrivateIpAddress"],
        "public_ip": instance.get("PublicIpAddress", None),
    }


@pytest.fixture
def instance_id(instance):
    """Return the instance ID."""
    return instance["id"]


@pytest.fixture
def instance_private_ip(instance):
    """Return the private IP for the instance."""
    return instance["private_ip"]


@pytest.fixture
def instance_public_ip(instance):
    """Return the public IP for the instance.

    Returns None if the instance does not have a public IP.
    """
    return instance["public_ip"]


@pytest.fixture
def instance_os(instance):
    """Return the instance OS."""
    return instance["os"]


# This is a "factory as fixture":
# https://docs.pytest.org/en/stable/how-to/fixtures.html#factories-as-fixtures
@pytest.fixture
def args(monkeypatch, vpc_id):
    """Return a function that can be used to set sys.argv for guacscanner."""

    def _args(log_level="debug"):
        """Set sys.argv for guacscanner."""
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "guacscanner",
                f"--log-level={log_level}",
                "--oneshot",
                "--postgres-hostname=localhost",
                "--postgres-password-file=tests/secrets/postgres-password",
                "--postgres-username-file=tests/secrets/postgres-username",
                "--private-ssh-key=dummy_key",
                "--rdp-password=dummy_rdp_password",
                "--rdp-username=dummy_rdp_username",
                "--vnc-password=dummy_vnc_password",
                "--vnc-username=dummy_vnc_username",
                f"--vpc-id={vpc_id}",
                "--windows-sftp-base=/C:/Users/dummy_user",
            ],
        )

    return _args


@pytest.fixture(scope="session")
def secrets_dir():
    """Path representing the location of the secrets for the Docker composition."""
    tests_dir = Path(__file__).parent
    d = Path(tests_dir, "secrets")
    d.mkdir()
    yield d
    d.rmdir()


def random_postgres_string(max_chars):
    """Return random string suitable for a PostgreSQL password.

    max_chars must be greater than 1.
    """
    source_chars = string.ascii_letters + string.digits + string.punctuation
    # flake8 and bandit give DUO102 and B311 errors, respectively, for
    # the use of random in this code, but since we're not using it for
    # cryptographic purposes it's OK.
    length = random.randint(1, max_chars - 2)  # noqa: DUO102 # nosec B311
    s = "".join(random.choices(source_chars, k=length))  # noqa: DUO102 # nosec B311
    # Inject a random special ASCII character sequence
    half = math.floor(length / 2)
    s = (
        s[: half + 1]
        + random.choice(SPECIAL_CHAR_SEQUENCES)  # noqa: DUO102 # nosec B311
        + s[half + 1 :]
    )

    return s


@pytest.fixture
def postgres_password_secret(secrets_dir):
    """Return a pathlib Path to the randomly-generated postgres password secret."""
    # Delete any existing file
    f = Path(secrets_dir, "postgres-password")
    f.unlink(missing_ok=True)

    # Generate and save a random password
    f.write_text(random_postgres_string(PASSWORD_MAX_LENGTH))
    yield f
    f.unlink()


@pytest.fixture(scope="session")
def postgres_username_secret(secrets_dir):
    """Return a pathlib Path to the postgres user name secret."""
    # Delete any existing file
    f = Path(secrets_dir, "postgres-username")
    f.unlink(missing_ok=True)

    # Save the user name
    f.write_text("dummy_user")
    yield f
    f.unlink()


@pytest.fixture
# We include the PostgreSQL password and username secret fixtures as
# arguments even though they are never used to ensure that they are
# created.
def dockerc(postgres_password_secret, postgres_username_secret):
    """Start up the Docker composition."""
    docker = DockerClient(compose_files=["tests/compose.yml"])
    docker.compose.up(detach=True, start=False, wait=True, wait_timeout=60)
    yield docker
    # Since this Docker composition includes data volumes, we want to
    # remove volumes as well when we bring the composition down so we
    # start from a clean slate next time.
    docker.compose.down(volumes=True)


@pytest.fixture
def postgres_container(dockerc):
    """Return the postgres container from the Docker composition."""
    dockerc.compose.up(detach=True, services=["postgres"], wait=True, wait_timeout=60)
    # Find the container by name even if it is stopped already
    yield dockerc.compose.ps(services=["postgres"], all=True)[0]
    dockerc.compose.down(services=["postgres"], timeout=60, volumes=True)


@pytest.fixture(scope="session")
def postgres_db_name():
    """Return the DB name to use when connecting to the postgres instance."""
    return "guacamole_db"


@pytest.fixture
def postgres_username(postgres_username_secret):
    """Return the username to use when connecting to the postgres instance."""
    return postgres_username_secret.read_text().strip()

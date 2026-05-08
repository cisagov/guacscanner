"""pytest plugin configuration.

https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins
"""

# Standard Python Libraries
import os
import random
import sys

# Third-Party Libraries
import boto3
from moto import mock_aws
import pytest
from python_on_whales import DockerClient


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


@pytest.fixture(scope="class")
def moto(aws_credentials):
    """Manually create a moto mock.

    Doing this instead of using the @mock_aws decorator allows us to
    control the scope.
    """
    mock = mock_aws()
    mock.start()
    yield mock
    mock.stop()


@pytest.fixture(scope="class")
def ec2(moto):
    """Mock EC2 boto3 client."""
    return boto3.client("ec2", "us-east-1")


@pytest.fixture(scope="class")
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


@pytest.fixture(scope="class")
def vpc_id(ec2, vpc_cidr):
    """Create a VPC and return the VPC ID."""
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr)
    return vpc["Vpc"]["VpcId"]


@pytest.fixture(scope="class")
def subnet_id(ec2, vpc_cidr, vpc_id):
    """Create a single subnet that takes up the entire VPC and return the subnet ID."""
    subnet = ec2.create_subnet(CidrBlock=vpc_cidr, VpcId=vpc_id)
    return subnet["Subnet"]["SubnetId"]


@pytest.fixture(scope="class", params=["Linux", "Windows"])
def instance(ec2, request, subnet_id):
    """Create an instance running the specified OS."""
    os = request.param
    if os.lower() == "linux":
        ami = "amzn-ami-hvm-2017.09.1.20171103-x86_64-gp2"
    elif os.lower() == "windows":
        ami = "Windows_Server-2016-English-Full-SQL_2017_Enterprise-2017.10.13"
    else:
        raise ValueError(f"{os} is not a valid value for the instance OS.")

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
        SubnetId=subnet_id,
        MaxCount=1,
        MinCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": os.capitalize()}],
            }
        ],
    )

    return {
        "id": response["Instances"][0]["InstanceId"],
        "os": os,
    }


@pytest.fixture(scope="class")
def instance_id(instance):
    """Return the instance ID."""
    return instance["id"]


@pytest.fixture(scope="class")
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
def dockerc():
    """Start up the Docker composition."""
    docker = DockerClient(compose_files=["tests/compose.yml"])
    docker.compose.up(detach=True, start=False, wait=True, wait_timeout=60)
    yield docker
    # Since this Docker composition includes data volumes, we want to
    # remove volumes as well when we bring the composition down so we
    # start from a clean slate next time.
    docker.compose.down(volumes=True)


# Using a scope of class here makes the PostgreSQL container have the
# same scope as the moto fixture.
@pytest.fixture(scope="class")
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


@pytest.fixture(scope="session")
def postgres_username():
    """Return the username to use when connecting to the postgres instance."""
    with open("tests/secrets/postgres-username") as file:
        postgres_username = file.read().strip()

    return postgres_username

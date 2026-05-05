"""Tests for guacscanner."""

# Standard Python Libraries
import logging
import os
import sys

# Third-Party Libraries
import boto3
from moto import mock_aws
import pytest

# cisagov Libraries
import guacscanner

LOG_LEVELS: list[str] = []
if sys.version_info >= (3, 11):
    LOG_LEVELS = [*logging.getLevelNamesMapping()]
else:
    # The logging.getLevelNamesMapping method was only introduced in
    # Python 3.11.
    LOG_LEVELS = [
        logging.getLevelName(x)
        for x in range(0, 101)
        if not logging.getLevelName(x).startswith("Level")
    ]

# define sources of version strings
RELEASE_TAG = os.getenv("RELEASE_TAG")
PROJECT_VERSION = guacscanner.__version__


class TestVersion:
    """Tests related to project version."""

    def test_stdout_version(self, capsys, monkeypatch):
        """Verify that version string sent to stdout agrees with the module version."""
        with pytest.raises(SystemExit):
            monkeypatch.setattr(sys, "argv", ["bogus", "--version"])
            guacscanner.guacscanner.main()
        captured = capsys.readouterr()
        assert (
            captured.out == f"{PROJECT_VERSION}\n"
        ), "standard output by '--version' should agree with module.__version__"

    def test_running_as_module(self, capsys, monkeypatch):
        """Verify that the __main__.py file loads correctly."""
        with pytest.raises(SystemExit):
            monkeypatch.setattr(sys, "argv", ["bogus", "--version"])
            # F401 is a "Module imported but unused" warning. This import
            # emulates how this project would be run as a module. The only thing
            # being done by __main__ is importing the main entrypoint of the
            # package and running it, so there is nothing to use from this
            # import. As a result, we can safely ignore this warning.
            # cisagov Libraries
            import guacscanner.__main__  # noqa: F401
        captured = capsys.readouterr()
        assert (
            captured.out == f"{PROJECT_VERSION}\n"
        ), "standard output by '--version' should agree with module.__version__"

    @pytest.mark.skipif(
        RELEASE_TAG in [None, ""], reason="this is not a release (RELEASE_TAG not set)"
    )
    def test_release_version(self):
        """Verify that release tag version agrees with the module version."""
        assert (
            RELEASE_TAG == f"v{PROJECT_VERSION}"
        ), "RELEASE_TAG does not match the project version"


@mock_aws
class TestLogLevels:
    """Tests related to setting the log level."""

    @pytest.mark.parametrize("level", LOG_LEVELS)
    @pytest.mark.usefixtures("dockerc")
    def test_log_levels(self, level, monkeypatch):
        """Validate commandline log-level arguments."""
        # Create a dummy VPC
        ec2 = boto3.client("ec2", "us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.19.74.0/24")
        vpc_id = vpc["Vpc"]["VpcId"]

        monkeypatch.setattr(
            sys,
            "argv",
            [
                f"--log-level={level}",
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
        monkeypatch.setattr(logging.root, "handlers", [])
        assert (
            logging.root.hasHandlers() is False
        ), "root logger should not have handlers yet"
        return_code = None
        try:
            guacscanner.guacscanner.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
            assert return_code is None, "main() should return success"
            assert (
                logging.root.hasHandlers() is True
            ), "root logger should now have a handler"
            assert (
                logging.getLevelName(logging.root.getEffectiveLevel()) == level.upper()
            ), f"root logger level should be set to {level.upper()}"
            assert return_code is None, "main() should return success"

    def test_bad_log_level(self, monkeypatch):
        """Validate bad log-level argument returns error."""
        monkeypatch.setattr(sys, "argv", ["bogus", "--log-level=emergency"])
        return_code = None
        try:
            guacscanner.guacscanner.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "main() should exit with error"


@mock_aws
class TestGuacuser:
    """Tests related to the addition of the guacuser."""

    def test_addition_of_guacuser(
        self, monkeypatch, postgres_container, postgres_db_name, postgres_username
    ):
        """Verify that adding the guacuser works as expected when it does not yet exist."""
        # Create a VPC
        ec2 = boto3.client("ec2", "us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.19.74.0/24")
        vpc_id = vpc["Vpc"]["VpcId"]

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "--log-level=debug",
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
        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT name FROM guacamole_entity;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "guacadmin" in response
        assert "guacuser" in response

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT COUNT(*) FROM guacamole_user;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "(1 row)" in response

    def test_addition_of_guacuser_already_exists(
        self, monkeypatch, postgres_container, postgres_db_name, postgres_username
    ):
        """Verify that adding the guacuser works as expected when it already exists."""
        self.test_addition_of_guacuser(
            monkeypatch, postgres_container, postgres_db_name, postgres_username
        )


@mock_aws
class TestLinuxInstance:
    """Tests related to Linux instances."""

    def test_instance_lifecycle(
        self, monkeypatch, postgres_container, postgres_db_name, postgres_username
    ):
        """Verify that adding then terminating an instance works as expected."""
        # Create and populate a VPC with an EC2 instance
        #
        # TODO: Create a test fixture to reduce duplication of this EC2
        # setup code.  See cisagov/guacscanner#7 for more details.
        ec2 = boto3.client("ec2", "us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.19.74.0/24")
        vpc_id = vpc["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(CidrBlock="10.19.74.0/24", VpcId=vpc_id)
        subnet_id = subnet["Subnet"]["SubnetId"]
        amis = ec2.describe_images(
            Filters=[
                {
                    "Name": "Name",
                    "Values": ["amzn-ami-hvm-2017.09.1.20171103-x86_64-gp2"],
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
                    "Tags": [{"Key": "Name", "Value": "Linux"}],
                }
            ],
        )
        instance_id = response["Instances"][0]["InstanceId"]

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "--log-level=debug",
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
        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "Linux" in response
        assert instance_id in response

        # Stop the existing EC2 instance
        ec2 = boto3.client("ec2", "us-east-1")
        ec2.stop_instances(InstanceIds=[instance_id])

        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "Linux" in response
        assert instance_id in response

        # Restart the existing EC2 instance
        ec2 = boto3.client("ec2", "us-east-1")
        ec2.start_instances(InstanceIds=[instance_id])

        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "Linux" in response
        assert instance_id in response

        # Terminate the existing EC2 instance
        ec2 = boto3.client("ec2", "us-east-1")
        ec2.terminate_instances(InstanceIds=[instance_id])

        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "(0 rows)" in response


@mock_aws
class TestWindowsInstance:
    """Tests related to Windows instances."""

    def test_instance_lifecycle(
        self, monkeypatch, postgres_container, postgres_db_name, postgres_username
    ):
        """Verify that adding then terminating an instance works as expected."""
        # Create and populate a VPC with an EC2 instance
        #
        # TODO: Create a test fixture to reduce duplication of this EC2
        # setup code.  See cisagov/guacscanner#7 for more details.
        ec2 = boto3.client("ec2", "us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.19.74.0/24")
        vpc_id = vpc["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(CidrBlock="10.19.74.0/24", VpcId=vpc_id)
        subnet_id = subnet["Subnet"]["SubnetId"]
        amis = ec2.describe_images(
            Filters=[
                {
                    "Name": "Name",
                    "Values": [
                        "Windows_Server-2016-English-Full-SQL_2017_Enterprise-2017.10.13"
                    ],
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
                    "Tags": [{"Key": "Name", "Value": "Windows"}],
                }
            ],
        )
        instance_id = response["Instances"][0]["InstanceId"]

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "--log-level=debug",
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
        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "Windows" in response
        assert instance_id in response

        # Stop the existing EC2 instance
        ec2 = boto3.client("ec2", "us-east-1")
        ec2.stop_instances(InstanceIds=[instance_id])

        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "Windows" in response
        assert instance_id in response

        # Restart the existing EC2 instance
        ec2 = boto3.client("ec2", "us-east-1")
        ec2.start_instances(InstanceIds=[instance_id])

        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "Windows" in response
        assert instance_id in response

        # Terminate the existing EC2 instance
        ec2 = boto3.client("ec2", "us-east-1")
        ec2.terminate_instances(InstanceIds=[instance_id])

        guacscanner.guacscanner.main()

        response = postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )
        assert "(0 rows)" in response

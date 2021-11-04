#!/usr/bin/env pytest -vs
"""Tests for guacscanner."""

# Standard Python Libraries
import logging
import os
import sys
from unittest.mock import MagicMock, patch

# Third-Party Libraries
import boto3
from moto import mock_ec2
import psycopg
import pytest

# cisagov Libraries
import guacscanner

log_levels = (
    "debug",
    "info",
    "warning",
    "error",
    "critical",
)

# define sources of version strings
RELEASE_TAG = os.getenv("RELEASE_TAG")
PROJECT_VERSION = guacscanner.__version__

DUMMY_VPC_ID = "vpc-0123456789abcdef0"


def test_stdout_version(capsys):
    """Verify that version string sent to stdout agrees with the module version."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
            guacscanner.guacscanner.main()
    captured = capsys.readouterr()
    assert (
        captured.out == f"{PROJECT_VERSION}\n"
    ), "standard output by '--version' should agree with module.__version__"


def test_running_as_module(capsys):
    """Verify that the __main__.py file loads correctly."""
    with pytest.raises(SystemExit):
        with patch.object(sys, "argv", ["bogus", "--version"]):
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
def test_release_version():
    """Verify that release tag version agrees with the module version."""
    assert (
        RELEASE_TAG == f"v{PROJECT_VERSION}"
    ), "RELEASE_TAG does not match the project version"


@mock_ec2
@pytest.mark.parametrize("level", log_levels)
def test_log_levels(level):
    """Validate commandline log-level arguments."""
    with patch.object(
        sys,
        "argv",
        [
            f"--log-level={level}",
            "--oneshot",
            "--postgres-password=dummy_db_password",
            "--postgres-username=dummy_db_username",
            "--private-ssh-key=dummy_key",
            "--rdp-password=dummy_rdp_password",
            "--rdp-username=dummy_rdp_username",
            "--vnc-password=dummy_vnc_password",
            "--vnc-username=dummy_vnc_username",
            f"--vpc-id={DUMMY_VPC_ID}",
        ],
    ):
        with patch.object(logging.root, "handlers", []):
            with patch.object(psycopg, "connect", return_value=MagicMock()):
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
                        logging.getLevelName(logging.root.getEffectiveLevel())
                        == level.upper()
                    ), f"root logger level should be set to {level.upper()}"
                    assert return_code is None, "main() should return success"


def test_bad_log_level():
    """Validate bad log-level argument returns error."""
    with patch.object(sys, "argv", ["bogus", "--log-level=emergency"]):
        return_code = None
        try:
            guacscanner.guacscanner.main()
        except SystemExit as sys_exit:
            return_code = sys_exit.code
        assert return_code == 1, "main() should exit with error"


@mock_ec2
def test_new_linux_instance():
    """Verify that adding a new Linux instance works as expected."""
    # Create and populate a VPC with an EC2 instance
    ec2 = boto3.client("ec2", "us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.19.74.0/24")
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(CidrBlock="10.19.74.0/24", VpcId=vpc_id)
    subnet_id = subnet["Subnet"]["SubnetId"]
    amis = ec2.describe_images(
        Filters=[
            {"Name": "Name", "Values": ["amzn-ami-hvm-2017.09.1.20171103-x86_64-gp2"]}
        ]
    )
    ami = amis["Images"][0]
    ami_id = ami["ImageId"]
    ec2.run_instances(
        ImageId=ami_id,
        SubnetId=subnet_id,
        MaxCount=1,
        MinCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "Linux"}]}
        ],
    )

    # Mock the PostgreSQL database connection
    mock_connection = MagicMock(
        name="Mock PostgreSQL connection", spec_set=psycopg.Connection
    )
    mock_cursor = MagicMock(name="Mock PostgreSQL cursor", spec_set=psycopg.Cursor)
    mock_cursor.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.side_effect = [{"count": 0}, {"connection_id": 1}]
    mock_connection.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    with patch.object(
        sys,
        "argv",
        [
            "--log-level=debug",
            "--oneshot",
            "--postgres-password=dummy_db_password",
            "--postgres-username=dummy_db_username",
            "--private-ssh-key=dummy_key",
            "--rdp-password=dummy_rdp_password",
            "--rdp-username=dummy_rdp_username",
            "--vnc-password=dummy_vnc_password",
            "--vnc-username=dummy_vnc_username",
            f"--vpc-id={vpc_id}",
        ],
    ):
        with patch.object(
            psycopg, "connect", return_value=mock_connection
        ) as mock_connect:
            guacscanner.guacscanner.main()
            mock_connect.assert_called_once()
            mock_connection.cursor.assert_called()
            mock_connection.commit.assert_called()
            mock_cursor.fetchone.assert_called()
            mock_cursor.execute.assert_called()
            mock_cursor.executemany.assert_called()


@mock_ec2
def test_terminated_instance():
    """Verify that adding a terminated instance works as expected."""
    # Create and populate a VPC with a terminated EC2 instance
    ec2 = boto3.client("ec2", "us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.19.74.0/24")
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(CidrBlock="10.19.74.0/24", VpcId=vpc_id)
    subnet_id = subnet["Subnet"]["SubnetId"]
    amis = ec2.describe_images(
        Filters=[
            {"Name": "Name", "Values": ["amzn-ami-hvm-2017.09.1.20171103-x86_64-gp2"]}
        ]
    )
    ami = amis["Images"][0]
    ami_id = ami["ImageId"]
    instances = ec2.run_instances(
        ImageId=ami_id,
        SubnetId=subnet_id,
        MaxCount=1,
        MinCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "Linux"}]}
        ],
    )
    instance_id = instances["Instances"][0]["InstanceId"]
    ec2.terminate_instances(InstanceIds=[instance_id])

    # Mock the PostgreSQL database connection
    mock_connection = MagicMock(
        name="Mock PostgreSQL connection", spec_set=psycopg.Connection
    )
    mock_cursor = MagicMock(name="Mock PostgreSQL cursor", spec_set=psycopg.Cursor)
    mock_cursor.__enter__.return_value = mock_cursor
    mock_connection.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    with patch.object(
        sys,
        "argv",
        [
            "--log-level=debug",
            "--oneshot",
            "--postgres-password=dummy_db_password",
            "--postgres-username=dummy_db_username",
            "--private-ssh-key=dummy_key",
            "--rdp-password=dummy_rdp_password",
            "--rdp-username=dummy_rdp_username",
            "--vnc-password=dummy_vnc_password",
            "--vnc-username=dummy_vnc_username",
            f"--vpc-id={vpc_id}",
        ],
    ):
        with patch.object(
            psycopg, "connect", return_value=mock_connection
        ) as mock_connect:
            guacscanner.guacscanner.main()
            mock_connect.assert_called_once()
            mock_connection.cursor.assert_called()
            mock_connection.commit.assert_called()
            mock_cursor.fetchone.assert_not_called()
            mock_cursor.execute.assert_called()
            mock_cursor.executemany.assert_not_called()


@mock_ec2
def test_stopped_instance():
    """Verify that adding a stopped instance works as expected."""
    # Create and populate a VPC with a stopped EC2 instance
    ec2 = boto3.client("ec2", "us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.19.74.0/24")
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(CidrBlock="10.19.74.0/24", VpcId=vpc_id)
    subnet_id = subnet["Subnet"]["SubnetId"]
    amis = ec2.describe_images(
        Filters=[
            {"Name": "Name", "Values": ["amzn-ami-hvm-2017.09.1.20171103-x86_64-gp2"]}
        ]
    )
    ami = amis["Images"][0]
    ami_id = ami["ImageId"]
    instances = ec2.run_instances(
        ImageId=ami_id,
        SubnetId=subnet_id,
        MaxCount=1,
        MinCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "Linux"}]}
        ],
    )
    instance_id = instances["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[instance_id])

    # Mock the PostgreSQL database connection
    mock_connection = MagicMock(
        name="Mock PostgreSQL connection", spec_set=psycopg.Connection
    )
    mock_cursor = MagicMock(name="Mock PostgreSQL cursor", spec_set=psycopg.Cursor)
    mock_cursor.__enter__.return_value = mock_cursor
    mock_connection.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    with patch.object(
        sys,
        "argv",
        [
            "--log-level=debug",
            "--oneshot",
            "--postgres-password=dummy_db_password",
            "--postgres-username=dummy_db_username",
            "--private-ssh-key=dummy_key",
            "--rdp-password=dummy_rdp_password",
            "--rdp-username=dummy_rdp_username",
            "--vnc-password=dummy_vnc_password",
            "--vnc-username=dummy_vnc_username",
            f"--vpc-id={vpc_id}",
        ],
    ):
        with patch.object(
            psycopg, "connect", return_value=mock_connection
        ) as mock_connect:
            guacscanner.guacscanner.main()
            mock_connect.assert_called_once()
            mock_connection.cursor.assert_called()
            mock_connection.commit.assert_called()


@mock_ec2
def test_new_windows_instance():
    """Verify that adding a new Windows instance works as expected."""
    # Create and populate a VPC with an EC2 instance
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
    ec2.run_instances(
        ImageId=ami_id,
        SubnetId=subnet_id,
        MaxCount=1,
        MinCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "Windows"}]}
        ],
    )

    # Mock the PostgreSQL database connection
    mock_connection = MagicMock(
        name="Mock PostgreSQL connection", spec_set=psycopg.Connection
    )
    mock_cursor = MagicMock(name="Mock PostgreSQL cursor", spec_set=psycopg.Cursor)
    mock_cursor.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.side_effect = [{"count": 0}, {"connection_id": 1}]
    mock_connection.__enter__.return_value = mock_connection
    mock_connection.cursor.return_value = mock_cursor

    with patch.object(
        sys,
        "argv",
        [
            "--log-level=debug",
            "--oneshot",
            "--postgres-password=dummy_db_password",
            "--postgres-username=dummy_db_username",
            "--private-ssh-key=dummy_key",
            "--rdp-password=dummy_rdp_password",
            "--rdp-username=dummy_rdp_username",
            "--vnc-password=dummy_vnc_password",
            "--vnc-username=dummy_vnc_username",
            f"--vpc-id={vpc_id}",
        ],
    ):
        with patch.object(
            psycopg, "connect", return_value=mock_connection
        ) as mock_connect:
            guacscanner.guacscanner.main()
            mock_connect.assert_called_once()
            mock_connection.cursor.assert_called()
            mock_connection.commit.assert_called()
            mock_cursor.fetchone.assert_called()
            mock_cursor.execute.assert_called()
            mock_cursor.executemany.assert_called()

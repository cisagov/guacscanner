"""Tests for guacscanner's get_connection_name helper."""

# Third-Party Libraries
import boto3
from moto import mock_aws

# cisagov Libraries
import guacscanner


class TestGetConnectionName:
    """Tests for the get_connection_name helper."""

    @staticmethod
    def __make_instance(tag_specs=None):
        """Create a moto-backed EC2 resource instance for testing.

        Passing tag_specs=None leaves the instance untagged, which is
        how boto3 reports an EC2 instance that has no tags at all
        (instance.tags is None in that case).
        """
        ec2 = boto3.resource("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/24")
        kwargs = {
            "ImageId": "ami-12345678",
            "MinCount": 1,
            "MaxCount": 1,
            "SubnetId": subnet.id,
        }
        if tag_specs is not None:
            kwargs["TagSpecifications"] = tag_specs
        instance = ec2.create_instances(**kwargs)[0]
        instance.reload()
        return instance

    @mock_aws
    def test_untagged_instance(self):
        """An instance with no tags should not raise (tags is None)."""
        instance = TestGetConnectionName.__make_instance()
        assert instance.tags is None

        name = guacscanner.guacscanner.get_connection_name(instance)

        # Falls back to the instance id when no Name tag is present.
        assert instance.id in name

    @mock_aws
    def test_no_name_tag(self):
        """An instance with tags but no Name tag should not raise."""
        instance = TestGetConnectionName.__make_instance(
            tag_specs=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Environment", "Value": "test"}],
                }
            ]
        )

        name = guacscanner.guacscanner.get_connection_name(instance)

        assert instance.id in name

    @mock_aws
    def test_name_tag_used_when_present(self):
        """The Name tag value is used when it is present."""
        instance = TestGetConnectionName.__make_instance(
            tag_specs=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": "webserver"}],
                }
            ]
        )

        name = guacscanner.guacscanner.get_connection_name(instance)

        assert name.startswith(f"webserver ({instance.id})")

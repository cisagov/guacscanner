"""Tests for guacscanner's get_connection_name helper."""

# Third-Party Libraries
import boto3

# cisagov Libraries
import guacscanner


class TestGetConnectionName:
    """Tests for the get_connection_name helper."""

    def test_untagged_instance(self, make_instance):
        """An instance with no tags should not raise (tags is None)."""
        instance = make_instance(tag_specs=None)
        assert instance.tags is None

        # We need to retrieve the resource as a boto3 resource for
        # compatibility with get_connection_name().
        instance_as_resource = boto3.resource("ec2").Instance(instance["id"])
        name = guacscanner.guacscanner.get_connection_name(instance_as_resource)

        # Falls back to the instance id when no Name tag is present.
        assert instance["id"] in name

    def test_no_name_tag(self, make_instance):
        """An instance with tags but no Name tag should not raise."""
        instance = make_instance(
            tag_specs=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Environment", "Value": "test"}],
                }
            ]
        )

        # We need to retrieve the resource as a boto3 resource for
        # compatibility with get_connection_name().
        instance_as_resource = boto3.resource("ec2").Instance(instance["id"])
        name = guacscanner.guacscanner.get_connection_name(instance_as_resource)

        assert instance["id"] in name

    def test_name_tag_used_when_present(self, make_instance):
        """The Name tag value is used when it is present."""
        instance = make_instance(
            tag_specs=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": "webserver"}],
                }
            ]
        )

        # We need to retrieve the resource as a boto3 resource for
        # compatibility with get_connection_name().
        instance_as_resource = boto3.resource("ec2").Instance(instance["id"])
        name = guacscanner.guacscanner.get_connection_name(instance_as_resource)

        assert name.startswith(f'webserver ({instance["id"]})')

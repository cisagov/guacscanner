"""Tests for guacscanner's get_connection_name helper."""

# cisagov Libraries
import guacscanner


class TestGetConnectionName:
    """Tests for the get_connection_name helper."""

    def test_untagged_instance(self, make_instance):
        """An instance with no tags should not raise (tags is None)."""
        instance = make_instance(tag_specs=None)
        assert instance.tags is None

        name = guacscanner.guacscanner.get_connection_name(instance)

        # Falls back to the instance id when no Name tag is present.
        assert instance.id in name

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

        name = guacscanner.guacscanner.get_connection_name(instance)

        assert instance.id in name

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

        name = guacscanner.guacscanner.get_connection_name(instance)

        assert name.startswith(f"webserver ({instance.id})")

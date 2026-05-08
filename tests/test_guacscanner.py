"""Tests for guacscanner."""

# Standard Python Libraries
import logging
import os
import sys

# Third-Party Libraries
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


class TestLogLevels:
    """Tests related to setting the log level."""

    @pytest.mark.parametrize("level", LOG_LEVELS)
    @pytest.mark.usefixtures("postgres_container")
    def test_log_levels(self, args, level, monkeypatch):
        """Validate commandline log-level arguments."""
        args(level)
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


class TestGuacuser:
    """Tests related to the addition of the guacuser."""

    @staticmethod
    def __query_entities(postgres_container, postgres_db_name, postgres_username):
        """Query the database for all guacamole entities."""
        return postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT name FROM guacamole_entity;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )

    @staticmethod
    def __query_users(postgres_container, postgres_db_name, postgres_username):
        """Query the database for a count of all guacamole users."""
        return postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT COUNT(*) FROM guacamole_user;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )

    def test_addition_of_guacuser(
        self, args, postgres_container, postgres_db_name, postgres_username
    ):
        """Verify that adding the guacuser works as expected."""
        # Verify that guacuser does not yet exist
        response = TestGuacuser.__query_entities(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "guacadmin" in response
        assert "guacuser" not in response

        args()
        # First run creates guacuser.
        guacscanner.guacscanner.main()

        response = TestGuacuser.__query_entities(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "guacadmin" in response
        assert "guacuser" in response

        response = TestGuacuser.__query_users(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response

    def test_addition_of_guacuser_already_exists(
        self, args, postgres_container, postgres_db_name, postgres_username
    ):
        """Verify that adding the guacuser works as expected when it already exists."""
        # Verify that guacuser already exists
        response = TestGuacuser.__query_entities(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "guacadmin" in response
        assert "guacuser" in response

        args()

        # Second run exercises the already-exists/idempotency path.
        guacscanner.guacscanner.main()

        response = TestGuacuser.__query_entities(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "guacadmin" in response
        assert "guacuser" in response

        response = TestGuacuser.__query_users(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response


class TestLinuxInstance:
    """Tests related to Linux instances."""

    @staticmethod
    def __query_connections(postgres_container, postgres_db_name, postgres_username):
        """Query the database for all guacamole connections."""
        return postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )

    def test_instance_creation(
        self,
        args,
        linux_instance_id,
        postgres_container,
        postgres_db_name,
        postgres_username,
    ):
        """Verify that adding an instance works as expected."""
        args()
        guacscanner.guacscanner.main()

        response = TestLinuxInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response
        assert "Linux" in response
        assert linux_instance_id in response

    def test_instance_stop(
        self,
        args,
        ec2,
        linux_instance_id,
        postgres_container,
        postgres_db_name,
        postgres_username,
    ):
        """Verify that stopping an instance works as expected."""
        # Stop the existing EC2 instance
        ec2.stop_instances(InstanceIds=[linux_instance_id])

        args()
        guacscanner.guacscanner.main()

        response = TestLinuxInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response
        assert "Linux" in response
        assert linux_instance_id in response

    def test_instance_restart(
        self,
        args,
        ec2,
        linux_instance_id,
        postgres_container,
        postgres_db_name,
        postgres_username,
    ):
        """Verify that restarting an instance works as expected."""
        # Restart the existing EC2 instance
        ec2.start_instances(InstanceIds=[linux_instance_id])

        args()
        guacscanner.guacscanner.main()

        response = TestLinuxInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response
        assert "Linux" in response
        assert linux_instance_id in response

    def test_instance_terminate(
        self,
        args,
        ec2,
        linux_instance_id,
        postgres_container,
        postgres_db_name,
        postgres_username,
    ):
        """Verify that terminating an instance works as expected."""
        # Terminate the existing EC2 instance
        ec2.terminate_instances(InstanceIds=[linux_instance_id])

        args()
        guacscanner.guacscanner.main()

        response = TestLinuxInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(0 rows)" in response


class TestWindowsInstance:
    """Tests related to Windows instances."""

    @staticmethod
    def __query_connections(postgres_container, postgres_db_name, postgres_username):
        """Query the database for all guacamole connections."""
        return postgres_container.execute(
            command=[
                "psql",
                "--command=SELECT connection_name FROM guacamole_connection;",
                f"--dbname={postgres_db_name}",
                f"--username={postgres_username}",
            ]
        )

    def test_instance_creation(
        self,
        args,
        postgres_container,
        postgres_db_name,
        postgres_username,
        windows_instance_id,
    ):
        """Verify that creating an instance works as expected."""
        args()
        guacscanner.guacscanner.main()

        response = TestWindowsInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response
        assert "Windows" in response
        assert windows_instance_id in response

    def test_instance_stop(
        self,
        args,
        ec2,
        postgres_container,
        postgres_db_name,
        postgres_username,
        windows_instance_id,
    ):
        """Verify that stopping an instance works as expected."""
        # Stop the existing EC2 instance
        ec2.stop_instances(InstanceIds=[windows_instance_id])

        args()
        guacscanner.guacscanner.main()

        response = TestWindowsInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response
        assert "Windows" in response
        assert windows_instance_id in response

    def test_instance_restart(
        self,
        args,
        ec2,
        postgres_container,
        postgres_db_name,
        postgres_username,
        windows_instance_id,
    ):
        """Verify that restarting an instance works as expected."""
        # Restart the existing EC2 instance
        ec2.start_instances(InstanceIds=[windows_instance_id])

        args()
        guacscanner.guacscanner.main()

        response = TestWindowsInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(1 row)" in response
        assert "Windows" in response
        assert windows_instance_id in response

    def test_instance_terminate(
        self,
        args,
        ec2,
        postgres_container,
        postgres_db_name,
        postgres_username,
        windows_instance_id,
    ):
        """Verify that terminating an instance works as expected."""
        # Terminate the existing EC2 instance
        ec2.terminate_instances(InstanceIds=[windows_instance_id])

        args()
        guacscanner.guacscanner.main()

        response = TestWindowsInstance.__query_connections(
            postgres_container, postgres_db_name, postgres_username
        )
        assert "(0 rows)" in response

"""pytest plugin configuration.

https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins
"""

# Third-Party Libraries
import pytest
from python_on_whales import docker


@pytest.fixture(scope="class")
def dockerc():
    """Start up the Docker composition."""
    docker.compose.up(detach=True)
    yield docker
    # Since this Docker composition includes data volumes, we want to
    # remove volumes as well when we bring the composition down so we
    # start from a clean slate next time.
    docker.compose.down(volumes=True)


@pytest.fixture(scope="class")
def guacamole_container(dockerc):
    """Return the guacamole container from the Docker composition."""
    # find the container by name even if it is stopped already
    return dockerc.compose.ps(services=["guacamole"], all=True)[0]


@pytest.fixture(scope="class")
def guacd_container(dockerc):
    """Return the guacd container from the Docker composition."""
    # find the container by name even if it is stopped already
    return dockerc.compose.ps(services=["guacd"], all=True)[0]


@pytest.fixture(scope="class")
def postgres_container(dockerc):
    """Return the postgres container from the Docker composition."""
    # find the container by name even if it is stopped already
    return dockerc.compose.ps(services=["postgres"], all=True)[0]


@pytest.fixture(scope="session")
def postgres_db_name():
    """Return string containing the DB name to use when connecting to the postgres instance running in the composition."""
    return "guacamole_db"


@pytest.fixture(scope="session")
def postgres_username():
    """Return string containing the username to use when connecting to the postgres instance running in the composition."""
    with open("src/secrets/postgres-username") as file:
        postgres_username = file.read().strip()

    return postgres_username

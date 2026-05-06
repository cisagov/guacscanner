"""pytest plugin configuration.

https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins
"""

# Third-Party Libraries
import pytest
from python_on_whales import DockerClient


@pytest.fixture(scope="session")
def dockerc():
    """Start up the Docker composition."""
    docker = DockerClient(compose_files=["tests/compose.yml"])
    docker.compose.up(detach=True, wait=True, wait_timeout=60)
    yield docker
    # Since this Docker composition includes data volumes, we want to
    # remove volumes as well when we bring the composition down so we
    # start from a clean slate next time.
    docker.compose.down(volumes=True)


# Using a scope of function here makes the PostgreSQL container have the
# same scope as the Moto mock AWS library.  The latter resets itself
# after every test function.
@pytest.fixture(scope="function")
def postgres_container(dockerc):
    """Return the postgres container from the Docker composition."""
    dockerc.compose.up(detach=True, services=["postgres"], wait=True, wait_timeout=60)
    # Find the container by name even if it is stopped already
    yield dockerc.compose.ps(services=["postgres"], all=True)[0]
    dockerc.compose.down(services=["postgres"], volumes=True)


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

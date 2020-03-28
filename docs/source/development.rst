Development
-----------

Install the test requirements with
``pip install -r test-requirements.txt``.

Install the project in pseudo-editable mode with ``flit install -s``.

Tests can be ran directly invoking ``pytest``.

This project uses `nox <https://nox.thea.codes/en/stable/>`_ to
automate testing and linting tasks. ``nox`` is installed as part of the
test requirements. Invoking ``nox`` will run all sessions, but you may
also run only some them, for example ``nox -s lint`` will only run the
linting session.

In order to test against a live proxy server a Docker setup is provided
based on the `Dante <https://www.inet.no/dante/>`_ SOCKS server.

A container will start ``danted`` listening on port 1080. The
docker-compose.yml will start the container and map the ports
appropriately. To start the container in the background:

::

    docker-compose -f docker/docker-compose.yml up -d

To stop it:

::

    docker-compose -f docker/docker-compose.yml down

Alternatively, remove the ``-d`` flag to run the containers in the
foreground.

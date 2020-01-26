#!/bin/bash

set -exo

docker-compose -f docker/docker-compose.yml up -d
# TODO: SOCKS4A doesn't seem to work correctly in Dante
# Wondering if this is a Dante bug? PySocks also doesn't work.
python examples/example_socks4.py
python examples/example_socks5.py

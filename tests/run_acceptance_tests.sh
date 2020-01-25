#!/bin/bash

docker-compose -f docker/docker-compose.yml up -d
python examples/example_socks4.py && python examples/example_socks5.py

# SOCKS

Client-side sans-I/O SOCKS proxy implementation.
Supports SOCKS4, SOCKS4A, and SOCKS5.

Each implementation follows the documents as listed below:

- SOCKS4: https://www.openssh.com/txt/socks4.protocol
- SOCKS4A: https://www.openssh.com/txt/socks4a.protocol
- SOCKS5: https://www.ietf.org/rfc/rfc1928.txt

## Development

Install the test requirements with `pip install -r test-requirements.txt`.

Tests can be ran directly invoking `pytest`.

This project uses [`nox`](https://nox.thea.codes/en/stable/) to automate
testing and linting tasks. `nox` is installed as part of the test requirements.
Invoking `nox` will run all sessions, but you may also run only some them, for
example `nox -s lint` will only run the linting session.

## License

MIT

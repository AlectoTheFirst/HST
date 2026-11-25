"""The paramiko transport offers no SHA-1 key exchange and no ssh-rsa host key."""

from __future__ import annotations

import socket

from hst.collectors import ssh


def test_the_paramiko_transport_offers_no_sha1_key_exchange_and_no_ssh_rsa():
    left, right = socket.socketpair()
    try:
        transport = ssh._transport_factory(left)
        try:
            options = transport.get_security_options()
            assert not [kex for kex in options.kex if kex.endswith("-sha1")]
            assert "ssh-rsa" not in options.key_types
        finally:
            transport.close()
    finally:
        left.close()
        right.close()

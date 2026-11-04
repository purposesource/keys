#!/usr/bin/env python3
"""ceremony-thumbprint.py - one participant's independent read of a signing key, for the key ceremony.

Pipe the vault's answer in, read your own result out loud:

    az keyvault key show --vault-name psn-prod-kv --name <KID> -o json | python3 ceremony-thumbprint.py

It prints the key's identity (vault, name, version), its properties (type, curve, operations,
exportable, enabled, created), whether the two coordinates are a real point on the P-256 curve, the
RFC 7638 JWK that is hashed, and the RFC 7638 thumbprint (base64url and hex). Nothing is written
anywhere. The key's PRIVATE half is never part of this answer: the vault cannot return it.

Standard library only (Python 3.8+), so it runs unchanged in Azure Cloud Shell or on a laptop.
Exit 0: a P-256 public key was read and its thumbprint printed. Exit 1: anything else, said plainly.
"""
import base64
import datetime
import hashlib
import json
import sys

# P-256 (secp256r1), SEC 2 section 2.4.2: y^2 = x^3 - 3x + b over GF(p).
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def fail(message):
    print('NOT OK: ' + message)
    sys.exit(1)


def coordinate(name, value):
    """The coordinate as the 32 bytes it encodes, and its unpadded base64url spelling."""
    if not isinstance(value, str) or not value:
        fail('the key carries no ' + name + ' coordinate')
    if any(c in value for c in '+/='):
        # A standard-base64 or padded spelling: the bytes are the same, the string a JWK carries is not.
        print('NOTE: ' + name + ' arrived as standard base64; it is converted to base64url for the thumbprint')
        raw = base64.b64decode(value + '=' * (-len(value) % 4))
    else:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if len(raw) != 32:
        fail(name + ' is ' + str(len(raw)) + ' bytes, not the 32 a P-256 coordinate has')
    spelled = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    if spelled != value and not any(c in value for c in '+/='):
        # The same 32 bytes under another final character (its two unused bits set): a published entry
        # must carry the canonical spelling, byte for byte (website tests/unit/jwks.test.mjs:174-175).
        fail(name + ' is spelled non-canonically (' + value + '); its canonical base64url is ' + spelled)
    return raw, spelled


def main():
    try:
        answer = json.load(sys.stdin)
    except ValueError as cause:
        fail('the input is not the JSON `az keyvault key show -o json` prints (' + str(cause) + ')')
    key = answer.get('key') if isinstance(answer, dict) and isinstance(answer.get('key'), dict) else answer
    attributes = answer.get('attributes', {}) if isinstance(answer, dict) else {}

    kid_url = str(key.get('kid', ''))
    parts = kid_url.split('/')
    vault = parts[2] if len(parts) > 2 else '(not stated)'
    name = parts[4] if len(parts) > 4 else '(not stated)'
    version = parts[5] if len(parts) > 5 else '(not stated)'
    kty = key.get('kty')
    crv = key.get('crv')
    ops = key.get('keyOps') or key.get('key_ops')
    print('vault         ' + vault)
    print('key name      ' + name + '   (the kid: one string, keyvault.bicep:94-95)')
    print('version       ' + version)
    print('type          ' + str(kty) + ' ' + str(crv))
    print('operations    ' + str(ops))
    for field in ('exportable', 'enabled', 'created', 'updated', 'recoveryLevel'):
        if field in attributes:
            value = attributes[field]
            if field in ('created', 'updated') and isinstance(value, (int, float)):
                value = datetime.datetime.utcfromtimestamp(value).strftime('%Y-%m-%dT%H:%M:%SZ')
            print(field.ljust(14) + str(value))

    if kty not in ('EC', 'EC-HSM') or crv != 'P-256':
        fail('this is not an EC P-256 key (type ' + str(kty) + ', curve ' + str(crv) + ')')
    if attributes.get('exportable') is True:
        fail('the vault reports this key as EXPORTABLE; a ceremony key must not be')

    x_raw, x = coordinate('x', key.get('x'))
    y_raw, y = coordinate('y', key.get('y'))
    xi = int.from_bytes(x_raw, 'big')
    yi = int.from_bytes(y_raw, 'big')
    on_curve = xi < P and yi < P and (yi * yi - (xi * xi * xi - 3 * xi + B)) % P == 0
    print('on P-256      ' + ('yes' if on_curve else 'NO'))
    if not on_curve:
        fail('the two coordinates are not a point on the P-256 curve')

    # RFC 7638 section 3.2: the required members of an EC key, in lexicographic order, no whitespace.
    canonical = json.dumps({'crv': 'P-256', 'kty': 'EC', 'x': x, 'y': y}, separators=(',', ':'), sort_keys=True)
    digest = hashlib.sha256(canonical.encode('utf-8')).digest()
    thumbprint = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    print('x             ' + x)
    print('y             ' + y)
    print('jwk hashed    ' + canonical)
    print('THUMBPRINT    ' + thumbprint)
    print('  (hex)       ' + digest.hex())
    print('read aloud    first 6: ' + thumbprint[:6] + '   last 6: ' + thumbprint[-6:])


if __name__ == '__main__':
    main()

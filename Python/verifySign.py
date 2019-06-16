#!/usr/bin/python3

import ecdsa
from hashlib import sha256

message = b'468'

# We hash "message" string into sha256
hash = sha256(message).hexdigest()

public_key = 'EE489B009194DC973D089738873FB7BD17B3673FB0596EBAAE7A36D6032CECEE98921068420DE70A978B2212DE6D3B0ECCC342F5CB42FD5C8E8B8F621DAADBE0'

sig = 'A5302D9ACF44184BCC017B0FC31BAE1A4EDA20A133D3447CB02C5E8DB19D688BCE5209E91170AB9E449A09BDB5C46E857685B7C5E8DC01E5AD3C62CDB41DC9A6'

vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.NIST256p)

isCorrect = vk.verify(bytes.fromhex(sig), message, hashfunc=sha256)

print('Is a valid key?: ' + str(isCorrect))

x = public_key[:64]
y = public_key[64:]
r = sig[:64]
s = sig[64:]

# We print the parameters for validateSignature as they are demanded by remix
# See: https://github.com/tdrerup/elliptic-curve-solidity/blob/master/contracts/curves/EllipticCurve.sol#$

print('"0x%s", ["0x%s", "0x%s"], ["0x%s", "0x%s"]'%(hash, r, s, x, y))

import json as _json
import logging as _logging
import os as _os
import os.path as _path
import sys as _sys

import rsa as _rsa

import fooster.web as _web


# address to listen on
addr = ('', 8000)

# directory to store information
dir = '/var/lib/mimameid'

# log locations
log = '/var/log/mimameid/mimameid.log'
http_log = '/var/log/mimameid/http.log'

# template directory to use
template = _path.dirname(__file__) + '/html'

# where texture service is located
service = 'http://textures.minecraft.net'

# whether to forward unknown requests to Mojang's Yggdrasil
forward = False


# runtime values based on config
_key_pub = None
_key_priv = None


# store config in env var
def _store():
    config = {key: val for key, val in globals().items() if not key.startswith('_')}

    _os.environ['MIMAMEID_CONFIG'] = _json.dumps(config)


# load config from env var
def _load():
    config = _json.loads(_os.environ['MIMAMEID_CONFIG'])

    globals().update(config)

    # automatically apply
    _apply()


# apply special config-specific logic after changes
def _apply():
    global _key_pub, _key_priv

    # setup logging
    if log:
        _logging.getLogger('mimameid').addHandler(_logging.FileHandler(log))
    else:
        _logging.getLogger('mimameid').addHandler(_logging.StreamHandler(_sys.stdout))

    if http_log:
        http_log_handler = _logging.FileHandler(http_log)
        http_log_handler.setFormatter(_web.HTTPLogFormatter())

        _logging.getLogger('http').addHandler(http_log_handler)

    # setup rsa key
    if _path.exists(dir + '/pub.key'):
        _logging.getLogger('mimameid').info('Loading RSA key...')

        with open(dir + '/pub.key', 'rb') as key_file:
            _key_pub = _rsa.PublicKey.load_pkcs1(key_file.read())
        with open(dir + '/priv.key', 'rb') as key_file:
            _key_priv = _rsa.PrivateKey.load_pkcs1(key_file.read())
    else:
        _logging.getLogger('mimameid').info('Generating RSA key...')

        _key_pub, _key_priv = _rsa.newkeys(2048)

        _os.makedirs(dir, exist_ok=True)

        with open(dir + '/pub.key', 'wb') as key_file:
            key_file.write(_key_pub.save_pkcs1())
        with open(dir + '/priv.key', 'wb') as key_file:
            key_file.write(_key_priv.save_pkcs1())

    # automatically store if not already serialized
    if 'MIMAMEID_CONFIG' not in _os.environ:
        _store()


# load if config already serialized in env var
if 'MIMAMEID_CONFIG' in _os.environ:
    _load()

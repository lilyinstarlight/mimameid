import json as _json
import logging as _logging
import os as _os
import os.path as _path
import sys as _sys

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
    # setup logging
    if log:
        _logging.getLogger('mimameid').addHandler(_logging.FileHandler(log))
    else:
        _logging.getLogger('mimameid').addHandler(_logging.StreamHandler(_sys.stdout))

    if http_log:
        http_log_handler = _logging.FileHandler(http_log)
        http_log_handler.setFormatter(_web.HTTPLogFormatter())

        _logging.getLogger('http').addHandler(http_log_handler)

    # automatically store if not already serialized
    if 'MIMAMEID_CONFIG' not in _os.environ:
        _store()


# load if config already serialized in env var
if 'MIMAMEID_CONFIG' in _os.environ:
    _load()

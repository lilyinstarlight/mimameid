import argparse
import logging
import signal
import sys

import fooster.web

from mimameid import config


parser = argparse.ArgumentParser(description='serve up an Yggdrasil-compatible authentication API')
parser.add_argument('-a', '--address', dest='address', help='address to bind')
parser.add_argument('-p', '--port', type=int, dest='port', help='port to bind')
parser.add_argument('-f', '--forward', type=bool, dest='forward', help='whether to forward unknown requests')
parser.add_argument('-t', '--template', dest='template', help='template directory to use')
parser.add_argument('-l', '--log', dest='log', help='log directory to use')
parser.add_argument('-d', '--dir', dest='dir', help='directory to store information')
parser.add_argument('service', nargs='?', help='uri of texture service')

args = parser.parse_args()

if args.address:
    config.addr = (args.address, config.addr[1])

if args.port:
    config.addr = (config.addr[0], args.port)

if args.forward:
    config.forward = args.forward

if args.template:
    config.template = args.template

if args.log:
    if args.log == 'none':
        config.log = None
        config.http_log = None
    else:
        config.log = args.log + '/mimameid.log'
        config.http_log = args.log + '/http.log'

if args.dir:
    config.dir = args.dir

if args.service:
    config.service = args.service


# setup logging
log = logging.getLogger('mimameid')
if config.log:
    log.addHandler(logging.FileHandler(config.log))
else:
    log.addHandler(logging.StreamHandler(sys.stdout))

if config.http_log:
    http_log_handler = logging.FileHandler(config.http_log)
    http_log_handler.setFormatter(fooster.web.HTTPLogFormatter())

    logging.getLogger('http').addHandler(http_log_handler)


from mimameid import name, version
from mimameid import http

log.info(name + ' ' + version + ' starting...')

# start everything
http.start()


# cleanup function
def exit():
    http.stop()


# use the function for both SIGINT and SIGTERM
for sig in signal.SIGINT, signal.SIGTERM:
    signal.signal(sig, exit)

# join against the HTTP server
http.join()

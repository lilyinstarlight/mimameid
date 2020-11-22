import argparse
import logging
import signal

from mimameid import config


def main():
    parser = argparse.ArgumentParser(description='serve up an Yggdrasil-compatible authentication API')
    parser.add_argument('-a', '--address', dest='address', help='address to bind')
    parser.add_argument('-p', '--port', type=int, dest='port', help='port to bind')
    parser.add_argument('-f', '--forward', dest='forward', action='store_true', help='whether to forward unknown requests')
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

    config._apply()


    from mimameid import __version__
    from mimameid import http

    log = logging.getLogger('mimameid')

    log.info('mimameid ' + __version__ + ' starting...')

    # start everything
    http.start()


    # cleanup function
    def exit(signum, frame):
        http.stop()


    # use the function for both SIGINT and SIGTERM
    for sig in signal.SIGINT, signal.SIGTERM:
        signal.signal(sig, exit)

    # join against the HTTP server
    http.join()


if __name__ == '__main__':
    main()

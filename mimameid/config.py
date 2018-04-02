# address to listen on
addr = ('', 8080)

# directory to store information
dir = '/var/lib/mimameid'

# log locations
log = '/var/log/mimameid/mimameid.log'
http_log = '/var/log/mimameid/http.log'

# template directory to use
import os.path
template = os.path.dirname(__file__) + '/html'

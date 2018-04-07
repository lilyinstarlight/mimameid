import os.path

# address to listen on
addr = ('', 8080)

# directory to store information
dir = '/var/lib/mimameid'

# log locations
log = '/var/log/mimameid/mimameid.log'
http_log = '/var/log/mimameid/http.log'

# template directory to use
template = os.path.dirname(__file__) + '/html'

# key directory to use
key = os.path.dirname(__file__) + '/key'

# where texture service is located
service = 'http://texture.minecraft.net'

# whether to forward unknown requests to Mojang's Yggdrasil
forward = True

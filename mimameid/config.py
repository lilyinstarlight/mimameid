import os.path

# address to listen on
addr = ('', 8000)

# directory to store information
dir = '/var/lib/mimameid'

# log locations
log = '/var/log/mimameid/mimameid.log'
http_log = '/var/log/mimameid/http.log'

# template directory to use
template = os.path.dirname(__file__) + '/html'

# where texture service is located
service = 'http://textures.minecraft.net'

# whether to forward unknown requests to Mojang's Yggdrasil
forward = False

import base64
import hashlib
import http.client
import json
import logging
import os
import random
import string
import time
import urllib.parse
import uuid

import httpx

import rsa

import fooster.web, fooster.web.file, fooster.web.form, fooster.web.json, fooster.web.page, fooster.web.query

import fooster.db

from mimameid import config


log = logging.getLogger('mimameid')

db = fooster.db.Database(config.dir + '/profiles.db', ['username', 'uuid', 'password', 'skin', 'cape', 'access', 'client', 'server'])
sessions = fooster.db.Database(config.dir + '/sessions.db', ['token', 'username', 'expire'])
timeout = 3600

key = (None, None)


class Key(fooster.web.HTTPHandler):
    def do_get(self):
        return 200, key[0].save_pkcs1(format='DER')


class Index(fooster.web.page.PageHandler):
    directory = config.template
    page = 'index.html'


class Login(fooster.web.page.PageHandler, fooster.web.form.FormHandler):
    directory = config.template
    page = 'login.html'
    message = ''

    def format(self, page):
        return page.format(message=self.message)

    def do_post(self):
        try:
            username = self.request.body['username']
            password = self.request.body['password']
        except (KeyError, TypeError):
            self.response.headers['Location'] = '/'
            return 303, ''

        token = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(32))

        if username in db and hashlib.sha256(password.encode('utf-8')).hexdigest() == db[username].password:
            delete = []
            for session in sessions:
                if session.expire <= time.time():
                    delete.append(session.token)
            for token in delete:
                del sessions[token]

            sessions[token] = sessions.Entry(username=username, expire=time.time() + timeout)

            self.response.headers['Set-Cookie'] = 'session={}; Max-Age={}'.format(token, timeout)
            self.response.headers['Location'] = '/edit'

            return 303, ''
        else:
            self.message = 'Username or password incorrect.'

        return self.do_get()


class Logout(fooster.web.HTTPHandler):
    def do_get(self):
        try:
            cookies = {cookie.split('=', 1)[0].strip(): cookie.split('=', 1)[1].strip() for cookie in self.request.headers['Cookie'].split(';')}

            delete = []
            for session in sessions:
                if session.expire <= time.time():
                    delete.append(session.token)
            for token in delete:
                del sessions[token]

            del sessions[cookies['session']]
        except (KeyError, IndexError):
            self.response.headers['Location'] = '/'
            return 303, ''

        self.response.headers['Set-Cookie'] = 'session=none; Max-Age=-1'
        self.response.headers['Location'] = '/login'

        return 303, ''


class Register(fooster.web.page.PageHandler, fooster.web.form.FormHandler):
    directory = config.template
    page = 'register.html'
    message = ''

    def format(self, page):
        return page.format(message=self.message)

    def do_post(self):
        try:
            username = self.request.body['username']
            password = self.request.body['password']
            confirm = self.request.body['confirm']
        except (KeyError, TypeError):
            self.response.headers['Location'] = '/'
            return 303, ''

        if len(username) >= 3 or len(username) <= 16:
            if password == confirm:
                if username not in db:
                    db[username] = db.Entry(str(uuid.uuid4()).replace('-', ''), hashlib.sha256(password.encode('utf-8')).hexdigest(), '', '', '', '', '')

                    self.response.headers['Location'] = '/login'

                    return 303, ''
                else:
                    self.message = 'Username already taken.'
            else:
                self.message = 'Passwords do not match.'
        else:
            self.message = 'Username not between 3 and 16 characters.'

        return self.do_get()


class Edit(fooster.web.page.PageHandler, fooster.web.form.FormHandler):
    directory = config.template
    page = 'edit.html'
    message = ''

    def format(self, page):
        return page.format(username=self.username, message=self.message)

    def do_get(self):
        try:
            cookies = {cookie.split('=', 1)[0].strip(): cookie.split('=', 1)[1].strip() for cookie in self.request.headers['Cookie'].split(';')}

            delete = []
            for session in sessions:
                if session.expire <= time.time():
                    delete.append(session.token)
            for token in delete:
                del sessions[token]

            self.username = sessions[cookies['session']].username
        except (KeyError, IndexError):
            self.response.headers['Location'] = '/'
            return 303, ''

        return super().do_get()

    def do_post(self):
        try:
            cookies = {cookie.split('=', 1)[0].strip(): cookie.split('=', 1)[1].strip() for cookie in self.request.headers['Cookie'].split(';')}

            self.username = sessions[cookies['session']].username
        except (KeyError, IndexError):
            self.response.headers['Location'] = '/'
            return 303, ''

        if self.username not in db:
            self.response.headers['Location'] = '/login'
            return 303, ''

        user = db[self.username]

        if 'password' in self.request.body and self.request.body['password']:
            user.password = hashlib.sha256(self.request.body['password'].encode('utf-8')).hexdigest()

        if 'skin' in self.request.body and 'filename' in self.request.body['skin'] and self.request.body['skin']['filename']:
            skin = self.request.body['skin']['file'].read()

            if user.skin:
                for other in db:
                    if user.skin == other.skin or user.skin == other.cape:
                        break
                else:
                    os.unlink(os.path.join(config.dir, 'texture', user.skin))

            user.skin = hashlib.sha256(skin).hexdigest()

            os.makedirs(os.path.join(config.dir, 'texture'), exist_ok=True)
            with open(os.path.join(config.dir, 'texture', user.skin), 'wb') as skin_file:
                skin_file.write(skin)

        self.message = 'Successfully updated profile.'

        return self.do_get()


class Authenticate(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            username = self.request.body['username']

            try:
                user = db[username]
            except KeyError:
                if config.forward:
                    request = httpx.post('https://authserver.mojang.com/authenticate', json=self.request.body)
                    return request.status_code, request.json()
                else:
                    raise fooster.web.HTTPError(403)

            if user.password != hashlib.sha256(self.request.body['password'].encode('utf-8')).hexdigest():
                raise fooster.web.HTTPError(403)

            user.access = ''.join(random.choice('1234567890abcdef') for _ in range(32))
            user.client = self.request.body['clientToken']

            data = {'accessToken': user.access, 'clientToken': user.client, 'availableProfiles': [{'id': user.uuid, 'name': user.username}], 'selectedProfile': {'id': user.uuid, 'name': user.username}}

            if 'requestUser' in self.request.body and self.request.body['requestUser']:
                data['user'] = {'id': user.uuid, 'properties': [{'name': 'preferredLanguage', 'value': 'en'}]}

            return 200, data
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)



class Refresh(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            user = None

            for other in db:
                if other.client == self.request.body['clientToken']:
                    user = other
                    break

            if not user or not user.access or user.access != self.request.body['accessToken']:
                if config.forward:
                    request = httpx.post('https://authserver.mojang.com/refresh', json=self.request.body)
                    return request.status_code, request.json()
                else:
                    raise fooster.web.HTTPError(403)

            user.access = ''.join(random.choice('1234567890abcdef') for _ in range(32))
            user.client = self.request.body['clientToken']

            data = {'accessToken': user.access, 'clientToken': user.client, 'availableProfiles': [{'id': user.uuid, 'name': user.username}], 'selectedProfile': {'id': user.uuid, 'name': user.username}}

            if 'requestUser' in self.request.body and self.request.body['requestUser']:
                data['user'] = {'id': user.uuid, 'properties': [{'name': 'preferredLanguage', 'value': 'en'}]}

            return 200, data
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Validate(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            user = None

            for other in db:
                if other.client == self.request.body['clientToken']:
                    user = other
                    break

            if not user or not user.access or user.access != self.request.body['accessToken'] or user.client != self.request.body['clientToken']:
                if config.forward:
                    request = httpx.post('https://authserver.mojang.com/validate', json=self.request.body)
                    return request.status_code, None if request.status_code == 204 else request.json()
                else:
                    raise fooster.web.HTTPError(403)

            return 204, None
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Signout(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            username = self.request.body['username']

            try:
                user = db[username]
            except KeyError:
                if config.forward:
                    request = httpx.post('https://authserver.mojang.com/signout', json=self.request.body)
                    return request.status_code, None if request.status_code == 204 else request.json()
                else:
                    raise fooster.web.HTTPError(403)

            if user.password != hashlib.sha256(self.request.body['password'].encode('utf-8')).hexdigest():
                raise fooster.web.HTTPError(403)

            user.access = ''

            return 204, None
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Invalidate(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            user = None

            for other in db:
                if other.client == self.request.body['clientToken']:
                    user = other
                    break

            if not user or not user.access or user.access != self.request.body['accessToken'] or user.client != self.request.body['clientToken']:
                if config.forward:
                    request = httpx.post('https://authserver.mojang.com/invalidate', json=self.request.body)
                    return request.status_code, None if request.status_code == 204 else request.json()
                else:
                    raise fooster.web.HTTPError(403)

            user.access = ''

            return 204, None
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Profile(fooster.web.json.JSONHandler):
    def do_post(self):
        usernames = []
        forward = []

        for username in self.request.body:
            try:
                user = db[username]

                usernames.append({'id': user.uuid, 'name': user.username})
            except KeyError:
                forward.append(username)

        if config.forward:
            usernames.extend(httpx.post('https://api.mojang.com/profiles/minecraft', json=forward).json())

        return 200, usernames


class Join(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            user = None

            for other in db:
                if other.uuid == self.request.body['selectedProfile']:
                    user = other
                    break

            if not user or not user.access or user.access != self.request.body['accessToken']:
                if config.forward:
                    request = httpx.post('https://sessionserver.mojang.com/session/minecraft/join', json=self.request.body)
                    return request.status_code, None if request.status_code == 204 else request.json()
                else:
                    raise fooster.web.HTTPError(403)

            user.server = self.request.body['serverId']

            return 204, None
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class HasJoined(fooster.web.query.QueryMixIn, fooster.web.json.JSONHandler):
    def do_get(self):
        try:
            for other in db:
                if other.username == self.request.query['username']:
                    user = other
                    break
            else:
                if config.forward:
                    response = httpx.get('https://sessionserver.mojang.com/session/minecraft/hasJoined' + self.groups['query'])

                    return response.status_code, response.json()
                else:
                    raise fooster.web.HTTPError(404)

            if user.server != self.request.query['serverId']:
                return 204, None

            textures = {'timestamp': int(round(time.time()*1000)), 'profileId': user.uuid, 'profileName': user.username, 'textures': {}}

            if user.skin:
                textures['textures']['SKIN'] = {'url': '{}/texture/{}'.format(config.service, user.skin)}

            if user.cape:
                textures['textures']['CAPE'] = {'url': '{}/texture/{}'.format(config.service, user.cape)}

            textures['signatureRequired'] = True

            textures_data = base64.b64encode(json.dumps(textures).encode('utf-8'))
            textures_signature = base64.b64encode(rsa.sign(textures_data, key[1], 'SHA-1'))

            return 200, {'id': user.uuid, 'name': user.username, 'properties': [{'name': 'textures', 'value': textures_data.decode(), 'signature': textures_signature.decode()}]}
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Session(fooster.web.query.QueryMixIn, fooster.web.json.JSONHandler):
    def do_get(self):
        for other in db:
            if other.uuid == self.groups['uuid']:
                user = other
                break
        else:
            if config.forward:
                response = httpx.get('https://sessionserver.mojang.com/session/minecraft/profile/' + self.groups['uuid'] + self.groups['query'])

                return response.status_code, response.json()
            else:
                raise fooster.web.HTTPError(404)

        textures = {'timestamp': int(round(time.time()*1000)), 'profileId': user.uuid, 'profileName': user.username, 'textures': {}}

        if user.skin:
            textures['textures']['SKIN'] = {'url': '{}/texture/{}'.format(config.service, user.skin)}

        if user.cape:
            textures['textures']['CAPE'] = {'url': '{}/texture/{}'.format(config.service, user.cape)}

        if 'unsigned' in self.request.query and not self.request.query['unsigned']:
            textures['signatureRequired'] = True

            textures_data = base64.b64encode(json.dumps(textures).encode('utf-8'))
            textures_signature = base64.b64encode(rsa.sign(textures_data, key[1], 'SHA-1'))

            return 200, {'id': user.uuid, 'name': user.username, 'properties': [{'name': 'textures', 'value': textures_data.decode(), 'signature': textures_signature.decode()}]}
        else:
            textures_data = base64.b64encode(json.dumps(textures).encode('utf-8'))

            return 200, {'id': user.uuid, 'name': user.username, 'properties': [{'name': 'textures', 'value': textures_data.decode()}]}


class Texture(fooster.web.file.PathHandler):
    local = config.dir + '/texture'
    remote = '/texture'

    def do_get(self):
        try:
            return super().do_get()
        except fooster.web.HTTPError as error:
            if error.code == 404 and config.forward:
                conn = http.client.HTTPSConnection('textures.minecraft.net')
                conn.request('GET', '/texture' + self.groups['path'])
                response = conn.getresponse()

                return response.status, response
            else:
                raise


class Meta(fooster.web.json.JSONHandler):
    def do_get(self):
        request = httpx.get('https://launchermeta.mojang.com/mc/' + self.groups['meta'])
        return request.status_code, request.json()


class Library(fooster.web.HTTPHandler):
    def do_get(self):
        conn = http.client.HTTPSConnection('libraries.minecraft.net')
        conn.request('GET', self.groups['path'])
        response = conn.getresponse()

        return response.status, response


class JSONErrorHandler(fooster.web.json.JSONErrorHandler):
    def respond(self):
        if self.error.code == 405:
            self.error.message = {'error': 'Method Not Allowed', 'errorMessage': 'A non-POST request was received'}
        elif self.error.code == 404:
            self.error.message = {'error': 'Not Found', 'errorMessage': 'Requested resource was not found'}
        elif self.error.code == 403:
            self.error.message = {'error': 'ForbiddenOperationException', 'errorMessage': 'Request included invalid credentials'}
        elif self.error.code == 400:
            self.error.message = {'error': 'IllegalArgumentException', 'errorMessage': 'Request included invalid fields'}

        return super().respond()


web = None

routes = {}
error_routes = {}


routes.update({'/key': Key, '/': Index, '/login': Login, '/logout': Logout, '/register': Register, '/edit': Edit, '/authenticate': Authenticate, '/refresh': Refresh, '/validate': Validate, '/signout': Signout, '/invalidate': Invalidate, '/profiles/minecraft': Profile, '/session/minecraft/join': Join, **fooster.web.query.new('/session/minecraft/hasJoined', HasJoined), **fooster.web.query.new('/session/minecraft/profile/(?P<uuid>[0-9a-f]{32})', Session), '/texture(?P<path>/.*)': Texture, '/mc/(?P<meta>.*)': Meta, '(?P<path>/.*\.jar)': Library})
error_routes.update({'[0-9]{3}': JSONErrorHandler})


def start():
    global key, web

    if os.path.exists(config.dir + '/pub.key'):
        log.info('Loading RSA key...')

        with open(config.dir + '/pub.key', 'rb') as key_file:
            key_pub = rsa.PublicKey.load_pkcs1(key_file.read())
        with open(config.dir + '/priv.key', 'rb') as key_file:
            key_priv = rsa.PrivateKey.load_pkcs1(key_file.read())

        key = (key_pub, key_priv)
    else:
        log.info('Generating RSA key...')

        key = rsa.newkeys(2048)

        os.makedirs(config.dir, exist_ok=True)

        with open(config.dir + '/pub.key', 'wb') as key_file:
            key_file.write(key[0].save_pkcs1())
        with open(config.dir + '/priv.key', 'wb') as key_file:
            key_file.write(key[1].save_pkcs1())

    web = fooster.web.HTTPServer(config.addr, routes, error_routes)
    web.start()


def stop():
    global web

    web.stop()
    web = None


def join():
    global web

    web.join()

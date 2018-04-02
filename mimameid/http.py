import base64
import hashlib
import json
import os
import random
import string
import time
import uuid

import fooster.web, fooster.web.file, fooster.web.form, fooster.web.json, fooster.web.page

import fooster.db

from mimameid import config


db = fooster.db.Database(config.dir + '/profiles.db', ['username', 'uuid', 'password', 'skin', 'cape', 'access', 'client'])
sessions = None


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

        session = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))

        if username in db and hashlib.sha256(password.encode('utf-8')).hexdigest() == db[username].password:
            sessions[session] = username

            self.response.headers['Set-Cookie'] = 'session={}; Max-Age=3600'.format(session)
            self.response.headers['Location'] = '/edit'

            return 303, ''
        else:
            self.message = 'Username or password incorrect.'

        return self.do_get()


class Logout(fooster.web.HTTPHandler):
    def do_get(self):
        cookies = {cookie.split('=', 1)[0].strip(): cookie.split('=', 1)[1].strip() for cookie in self.request.headers['Cookie'].split(';')}

        try:
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

        if password == confirm:
            if username not in db:
                db[username] = db.Entry(str(uuid.uuid4()).replace('-', ''), hashlib.sha256(password.encode('utf-8')).hexdigest(), '', '', '', '')

                self.response.headers['Location'] = '/login'

                return 303, ''
            else:
                self.message = 'Username already taken.'
        else:
            self.message = 'Passwords do not match.'

        return self.do_get()


class Edit(fooster.web.page.PageHandler, fooster.web.form.FormHandler):
    directory = config.template
    page = 'edit.html'
    message = ''

    def format(self, page):
        cookies = {cookie.split('=', 1)[0].strip(): cookie.split('=', 1)[1].strip() for cookie in self.request.headers['Cookie'].split(';')}

        try:
            return page.format(username=sessions[cookies['session']], message=self.message)
        except (KeyError, IndexError):
            raise fooster.web.HTTPError(400)

    def do_post(self):
        cookies = {cookie.split('=', 1)[0].strip(): cookie.split('=', 1)[1].strip() for cookie in self.request.headers['Cookie'].split(';')}

        try:
            username = sessions[cookies['session']]
        except (KeyError, IndexError):
            self.response.headers['Location'] = '/'
            return 303, ''

        if username not in db:
            self.response.headers['Location'] = '/login'
            return 303, ''

        user = db[username]

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
            user = db[self.request.body['username']]

            if user.password != hashlib.sha256(self.request.body['password']).hexdigest():
                raise fooster.web.HTTPError(403)

            user.access = ''.join(random.choice('1234567890abcdef') for _ in range(16))
            user.client = self.request.body['clientToken']

            return 200, {'accessToken': user.access, 'clientToken': user.client, 'availableProfiles': [{'id': user.uuid, 'name': user.username}], 'selectedProfile': {'id': user.uuid, 'name': user.username}, 'user': {'id': user.uuid, 'properties': [{'name': 'preferredLanguage', 'value': 'en'}]}}
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)



class Refresh(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            for other in db:
                if other.client == self.request.body['clientToken']:
                    user = other
                    break
            else:
                raise fooster.web.HTTPError(404)

            if not user.access or user.access != self.request.body['accessToken']:
                raise fooster.web.HTTPError(403)

            user.access = ''.join(random.choice('1234567890abcdef') for _ in range(16))
            user.client = self.request.body['clientToken']

            return 200, {'accessToken': user.access, 'clientToken': user.client, 'availableProfiles': [{'id': user.uuid, 'name': user.username}], 'selectedProfile': {'id': user.uuid, 'name': user.username}, 'user': {'id': user.uuid, 'properties': [{'name': 'preferredLanguage', 'value': 'en'}]}}
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Validate(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            for other in db:
                if other.client == self.request.body['clientToken']:
                    user = other
                    break
            else:
                raise fooster.web.HTTPError(404)

            if not user.access or user.access != self.request.body['accessToken'] or user.client != self.request.body['clientToken']:
                raise fooster.web.HTTPError(403)

            return 204, ''
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Signout(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            user = db[self.request.body['username']]

            if user.password != hashlib.sha256(self.request.body['password']).hexdigest():
                raise fooster.web.HTTPError(403)

            user.access = ''

            return 204, ''
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Invalidate(fooster.web.json.JSONHandler):
    def do_post(self):
        try:
            for other in db:
                if other.client == self.request.body['clientToken']:
                    user = other
                    break
            else:
                raise fooster.web.HTTPError(404)

            if not user.access or user.access != self.request.body['accessToken'] or user.client != self.request.body['clientToken']:
                raise fooster.web.HTTPError(403)

            user.access = ''

            return 204, ''
        except (KeyError, TypeError):
            raise fooster.web.HTTPError(400)


class Profile(fooster.web.json.JSONHandler):
    def do_post(self):
        usernames = []

        print(self.request.body)
        for username in self.request.body:
            try:
                user = db[username]

                usernames.append({'id': user.uuid, 'name': user.username})
            except KeyError:
                pass

        return 200, usernames


class Session(fooster.web.json.JSONHandler):
    def do_get(self):
        for other in db:
            if other.uuid == self.groups[0]:
                user = other
                break
        else:
            raise fooster.web.HTTPError(404)

        textures = {'timestamp': int(round(time.time()*1000)), 'profileId': user.uuid, 'profileName': user.username, 'textures': {}}

        if user.skin:
            textures['textures']['SKIN'] = 'http://textures.minecraft.net/texture/{}'.format(user.skin)

        if user.cape:
            textures['textures']['CAPE'] = 'http://textures.minecraft.net/texture/{}'.format(user.cape)

        return 200, {'id': user.uuid, 'name': user.username, 'properties': [{'name': 'textures', 'value': base64.b64encode(json.dumps(textures).encode('utf-8')).decode()}]}


http = None

routes = {}
error_routes = {}


routes.update({'/': Index, '/login': Login, '/logout': Logout, '/register': Register, '/edit': Edit, '/authenticate': Authenticate, '/refresh': Refresh, '/validate': Validate, '/signout': Signout, '/invalidate': Invalidate, '/profiles/minecraft': Profile, '/session/minecraft/profile/([0-9a-f]{32})': Session})
routes.update(fooster.web.file.new(config.dir + '/texture', '/texture'))
error_routes.update(fooster.web.json.new_error())


def start():
    global http, sessions

    http = fooster.web.HTTPServer(config.addr, routes, error_routes)
    sessions = http.sync.dict()
    http.start()


def stop():
    global http, sessions

    http.stop()
    sessions = None
    http = None


def join():
    global http

    http.join()

#!/usr/bin/env python
# main codebase for the Udacity wiki project

# imports
import os
import re
import time
import webapp2
import jinja2
import logging
import datetime
import json
from lib import utils

from google.appengine.ext import db
from google.appengine.api import memcache


# setup jinja2 templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = utils.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and utils.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# page wiki stufff

class Page(db.Model):
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    # note that the key name is the path of the page and added when the page is posted to the server

    def by_id(cls, uid):
    	return Page.get_by_id(uid)

class WikiPage(BlogHandler):
	
    def get(self, page_id):
		key = db.Key.from_path('Page', str(page_id))
		page = db.get(key)

		if not page:
			self.redirect('/_edit' + page_id)
		else:
		    content = page.content
		    self.render("page.html", content=content, page_id=page_id)

class EditPage(BlogHandler):
    def get(self, page_id):
        key = db.Key.from_path('Page', str(page_id))
        page = db.get(key)

        if not page:
            content = ""
            self.render("edit.html", content=content, page_id=page_id)
        else:
            content = page.content
            self.render("edit.html", content=content, page_id=page_id)

    def post(self, page_id):
        if not self.user:
    		self.redirect('/')

        content = self.request.get('content')
        page = Page(key_name=page_id, content=content)
        page.put()
        self.redirect(page_id)


##### user stuff

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = utils.make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and utils.valid_pw(name, pw, u.pw_hash):
            return u

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not utils.valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not utils.valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not utils.valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            #make sure the user doesn't already exist
	        u = User.by_name(self.username)
	        if u:
	            msg = 'That user already exists.'
	            self.render('signup-form.html', error_username = msg)
	        else:
	            u = User.register(self.username, self.password, self.email)
	            u.put()
	            
	            self.login(u)
	            self.redirect('/')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


# URL routing

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
	('/login', Login),
	('/logout', Logout),
	('/_edit' + PAGE_RE, EditPage),
	(PAGE_RE, WikiPage)]
	,debug=True)
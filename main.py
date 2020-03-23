from google.appengine.api import users
from google.appengine.ext import ndb

import os
import urllib

import jinja2
import webapp2
from webapp2_extras import sessions

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


def user_key(user_name):
    return ndb.Key('User', user_name)


def auth_guard(self):
    if self.session.get('user_id') == '' or self.session.get('user_name') == '':
        self.redirect("/")


class User(ndb.Model):
    id = ndb.KeyProperty(kind='User', repeated=False)
    name = ndb.StringProperty(indexed=True)
    password = ndb.StringProperty(indexed=True)


class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()


class LoginPage(BaseHandler):

    def get(self):
        # user = User( id = user_key('s3752764'), name = "George Joseph" , password="123456")
        # user.put();

        # Already logged in check
        if self.session.get('user_id') != '' and self.session.get('user_name') != '':
            self.redirect("/main")

        template_values = {
            'errors': []
        }
        template = JINJA_ENVIRONMENT.get_template('login.html')
        self.response.write(template.render(template_values))

    def post(self):
        user_name = self.request.get("username")
        # user_name = 's3752764'
        password = self.request.get("password")
        errors = {'user_name': [], 'password': [], 'form': []}

        if user_name == '':
            errors['user_name'].append("Please enter username")
        if password == '':
            errors['password'].append("Please enter password")

        user_data = []

        if errors['user_name'] == [] and errors['password'] == []:
            user_query = User.query().filter(User.id == user_key(
                user_name)).filter(User.password == password)
            user_data = user_query.fetch(1)

            if len(user_data) >= 1:
                template_values = {
                    'errors': errors
                }
                self.session['user_name'] = user_data[0].name
                self.session['user_id'] = user_name
                return self.redirect('/main')
            else:
                errors['form'].append("User id or password is invalid")
                template_values = {
                    'errors': errors
                }
                template = JINJA_ENVIRONMENT.get_template('login.html')
                self.response.write(template.render(template_values))
        else:
            template_values = {
                'errors': errors
            }
            template = JINJA_ENVIRONMENT.get_template('login.html')
            self.response.write(template.render(template_values))


class MainPage(BaseHandler):
    def get(self):
        # Authentication guard
        auth_guard(self)

        template_values = {
            'user_name': self.session.get('user_name'),
            'user_id': self.session.get('user_id')
        }
        template = JINJA_ENVIRONMENT.get_template('main.html')
        self.response.write(template.render(template_values))


class NamePage(BaseHandler):
    def get(self):
        # Authentication guard
        auth_guard(self)

        template_values = {
            'user_name': self.session.get('user_name'),
            'user_id': self.session.get('user_id'),
            'errors': []
        }
        template = JINJA_ENVIRONMENT.get_template('name.html')
        self.response.write(template.render(template_values))

    def post(self):
        # Authentication guard
        auth_guard(self)

        user_name = self.request.get('user_name')

        success = False
        errors = {'user_name': []}
        if user_name == '':
            errors['user_name'].append("User name cannot be empty")
        else:
            key = user_key(self.session.get('user_id'))
            user_record = User.query().filter(User.id == key).fetch(1)
            user_record[0].name = user_name
            user_record[0].put()
            self.session['user_name'] = user_record[0].name
            success = True

        template_values = {
            'user_name': self.session.get('user_name'),
            'user_id': self.session.get('user_id'),
            'errors': errors,
            'success': success
        }
        template = JINJA_ENVIRONMENT.get_template('name.html')
        self.response.write(template.render(template_values))


# Controller for password Change page
class PasswordPage(BaseHandler):
    def get(self):
        # Authentication guard
        auth_guard(self)

        # Render the UI with the data in session
        template_values = {
            'user_name': self.session.get('user_name'),
            'user_id': self.session.get('user_id'),
            'errors': [],
        }
        template = JINJA_ENVIRONMENT.get_template('password.html')
        self.response.write(template.render(template_values))

    # Password Change post request handler
    def post(self):
        # Authentication guard
        auth_guard(self)

        old_password = self.request.get('old_password')
        new_password = self.request.get('new_password')

        errors = {'old_password': [], 'new_password': []}

        # Form validation for empty fields
        if old_password == '':
            errors['old_password'].append("Please enter old password")
        if new_password == '':
            errors['new_password'].append("Please enter new password")

        # If there are no empty field errors
        if errors['old_password'] == [] and errors['new_password'] == []:
            # Fetching the user record from datastore
            key = user_key(self.session.get('user_id'))
            user_record = User.query().filter(User.id == key).filter(
                User.password == old_password).fetch(1)

            # If data fetched successfully
            if len(user_record) >= 1:
                user_record[0].password = new_password
                user_record[0].put()
                template_values = {
                    'user_name': self.session.get('user_name'),
                    'user_id': self.session.get('user_id'),
                    'errors': errors,
                    'success': True
                }
                template = JINJA_ENVIRONMENT.get_template('password.html')
                self.response.write(template.render(template_values))
            else:
                # If the pasword did not match
                errors['old_password'].append("User password is incorrect")
                template_values = {
                    'user_name': self.session.get('user_name'),
                    'user_id': self.session.get('user_id'),
                    'errors': errors,
                    'success': False
                }

                template = JINJA_ENVIRONMENT.get_template('password.html')
                self.response.write(template.render(template_values))
        # If there are empty fields
        else:
            template_values = {
                'user_name': self.session.get('user_name'),
                'user_id': self.session.get('user_id'),
                'errors': errors,
                'success': False
            }
            template = JINJA_ENVIRONMENT.get_template('password.html')
            self.response.write(template.render(template_values))


class Logout(BaseHandler):
    def get(self):
        self.session['user_name'] = ""
        self.session['user_id'] = ""
        self.redirect("/")


config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'my-super-secret-key',
}
config['debug'] = True

application = webapp2.WSGIApplication([
    ('/', LoginPage),
    ('/authenticate', LoginPage),
    ('/main', MainPage),
    ('/Name', NamePage),
    ('/Password', PasswordPage),
    ('/Logout', Logout)

], config=config)


def main():
    application.run()


if __name__ == "__main__":
    main()

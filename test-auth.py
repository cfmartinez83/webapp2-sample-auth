import webapp2
import os
from handlers import *

webapp2_config = {}
webapp2_config['webapp2_extras.sessions'] = {
    'secret_key': 'Im_an_alien',
}

app = webapp2.WSGIApplication([
    webapp2.Route(r'/login/', handler=LoginHandler, name='login'),
    webapp2.Route(r'/logout/', handler=LogoutHandler, name='logout'),
    webapp2.Route(r'/secure/', handler=SecureRequestHandler, name='secure'),
    webapp2.Route(r'/create/', handler=CreateUserHandler, name='create-user'),
], config=webapp2_config)


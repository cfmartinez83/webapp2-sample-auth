from webapp2_extras.appengine.auth.models import User as WebApp2UserModel
#from ndb import key, model
from google.appengine.ext import ndb

class User(WebApp2UserModel): # child class of User
    firstname = ndb.StringProperty()
    lastname = ndb.StringProperty()
    email = ndb.StringProperty()


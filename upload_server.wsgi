
# -*- python -*-
import os
import sys

# this is needed to prevent threading issues with mod_wsgi, e.g.
# ImportError: Failed to import _strptime because the import lockis held by another thread.
# might be fixed in python 3
# see: https://code.google.com/p/modwsgi/issues/detail?id=177

from datetime import datetime
datetime.strptime('01/14/2014', '%m/%d/%Y')

sys.path.append(os.path.dirname(__file__))
sys.path.append('/var/www/upload_server/venv2')
os.environ['PYTHON_EGG_CACHE'] = '/var/www/upload_server'
os.environ['DJANGO_SETTINGS_MODULE'] = 'upload_server.settings'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()











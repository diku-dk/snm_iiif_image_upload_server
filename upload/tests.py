#import requests 
import os
import io
import hmac
import json
import hashlib
from datetime import datetime
from django.urls import resolve
from django.test import TestCase, Client
from django.conf import settings
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from django.contrib.auth.models import User

from upload.views import homepage

SECRET_KEY = settings.SECRET_KEY

# Create your tests here.
class BasicTest(TestCase):
    
    #def test_homepage_resolves(self):
    #    found = resolve('/')
    #    self.assertEqual(found.func, homepage)
    
    def test_image_folder_exists(self):
        self.assertEqual(os.path.exists(settings.IMAGE_FOLDER), True, 'Image folder specified in settings does not exist')
        
    def test_cache_folder_exists(self):
        self.assertEqual(os.path.exists(settings.CACHE_FOLDER), True, 'CACHE folder specified in settings does not exist')
    
    def test_upload(self):
        user = User.objects.create_user('captain', password='serenity')
        token_user = Token.objects.create(user=user)
        file_path = 'img.jpg'
        fn = os.path.basename(file_path)
        specify_user = 'TheCaptain'
        timestamp = str(datetime.utcnow())
        img = open(file_path, 'rb')
        md5 = get_md5(img)
        img = open(file_path, 'rb')
        
        to_hash = bytes(fn + '\n' + specify_user + '\n' + timestamp + '\n' + md5).encode('latin-1')#python3:, 'latin-1'
        hmac_sig = hmac.new(bytes(SECRET_KEY), to_hash, hashlib.sha512).hexdigest().encode('latin-1')#python3:, 'latin-1'
        files = {'file': img,
                 'fn':fn, 
                 'specify_user':specify_user,
                 'timestamp':timestamp,
                 'md5_sum': md5,
                 'hmac_sig': hmac_sig,
                }
        
       
        token = Token.objects.get(user__username='captain')
        
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        
        r = client.post('/imageUpload/', data=files)
        self.assertEqual(r.status_code, 200, r.data)
        new_fn = r.content.decode('utf-8').split('"')[1]
        new_fp = os.path.join(settings.IMAGE_FOLDER,new_fn)
        os.remove(new_fp)
        
        
    def test_bad_upload(self):
        #test what happens if hmac incorrect.
        user = User.objects.create_user('captain', password='serenity')
        token_user = Token.objects.create(user=user)
        file_path = 'img.jpg'
        fn = os.path.basename(file_path)
        specify_user = 'TheCaptain'
        timestamp = str(datetime.utcnow())
        img = open(file_path, 'rb')
        md5 = get_md5(img)
        img = open(file_path, 'rb')
        
        to_hash = bytes(fn + '\n' + specify_user + '\n' + timestamp + '\n' + md5 +'blah' ).encode('latin-1')#python3:, 'latin-1'
        hmac_sig = hmac.new(bytes(SECRET_KEY), to_hash, hashlib.sha512).hexdigest().encode('latin-1')#python3:, 'latin-1'
        
        files = {'file': img,
                 'fn':fn, 
                 'specify_user':specify_user,
                 'timestamp':timestamp,
                 'md5_sum': md5,
                 'hmac_sig': hmac_sig,
                }
        
       
        token = Token.objects.get(user__username='captain')
        
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        
        r = client.post('/imageUpload/', data=files)
        self.assertEqual(r.status_code, 222, r.data)

    def test_raw_upload(self):
        user = User.objects.create_user('captain', password='serenity')
        token_user = Token.objects.create(user=user)
        file_path = 'raw.CR2'
        fn = os.path.basename(file_path)
        specify_user = 'TheCaptain'
        timestamp = str(datetime.utcnow())
        img = open(file_path, 'rb')
        md5 = get_md5(img)
        img = open(file_path, 'rb')
        
        to_hash = bytes(fn + '\n' + specify_user + '\n' + timestamp + '\n' + md5).encode('latin-1')#python3:, 'latin-1'
        hmac_sig = hmac.new(bytes(SECRET_KEY), to_hash, hashlib.sha512).hexdigest().encode('latin-1')#python3:, 'latin-1'
        files = {'file': img,
                 'fn':fn, 
                 'specify_user':specify_user,
                 'timestamp':timestamp,
                 'md5_sum': md5,
                 'hmac_sig': hmac_sig,
                }
        
       
        token = Token.objects.get(user__username='captain')
        
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        
        r = client.post('/imageUpload/', data=files)
        self.assertEqual(r.status_code, 200, r.data)
        new_fn = r.content.decode('utf-8').split('"')[1]
        new_fp = os.path.join(settings.IMAGE_FOLDER,new_fn)
        print(new_fn)
        #os.remove(new_fp)
        
def split_filename(fn):
    return '.'.join(fn.split('.')[:-1]), fn.split('.')[-1]
        
def get_md5(img):
    return hashlib.md5(img.read()).hexdigest()
    
        
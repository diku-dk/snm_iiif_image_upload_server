import os
import hmac
import hashlib
import logging
import datetime
import subprocess

from uuid import uuid4
from ipware import get_client_ip
from django.conf import settings
from django.shortcuts import render
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

logger = logging.getLogger(__name__)

SECRET_KEY = settings.SECRET_KEY


# Create your views here.
def homepage(request):
    return HttpResponse('Hello (again) World!');

class HelloView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        content = {'message':'Hello, World!'}
        return Response(content)

def split_filename(fn):
    return '.'.join(fn.split('.')[:-1]), fn.split('.')[-1]
    
    
class FileUploadView(APIView):
    parser_classes = (MultiPartParser, )
    permission_classes = (IsAuthenticated,)

    def post(self, request, format='jpg'):
        ip, _ = get_client_ip(request)
        user = request._user
        specify_user = request.data.get('specify_user','UNSPECIFIED')
        orig_fn = request.data.get('fn','UNSPECIFIED')
        timestamp = request.data.get('timestamp','0000-00-00 00:00:00.000000')
        sent_hmac_sig = request.data.get('hmac_sig','').encode('latin-1')
        
        _, fmt = split_filename(orig_fn)
        if fmt.lower() not in settings.IMAGE_FORMATS:
            return BadImageFormatResponse(fmt)
        
        
        
        uuid = make_uuid()
        fn = uuid + '.' + fmt
        logger.info("Attempting upload, server user: %s, specify user: %s, ip: %s, original filename: %s, filename: %s"%(user,specify_user,ip,orig_fn,fn))
        
        img = request.FILES['file']
        cache_fp = os.path.join(settings.CACHE_FOLDER, fn)

        if is_old_timestamp(timestamp):
            logger.warning("FAILED: Attempt to upload with old timestamp, or without timestamp. uuid: %s"%uuid)
            return OldTimestampResponse(timestamp)
        
        md5 = get_md5(img)
        to_hash = bytes(orig_fn + '\n' + specify_user + '\n' + timestamp + '\n' + md5).encode('latin-1')
        received_hmac_sig = hmac.new(bytes(SECRET_KEY), to_hash, hashlib.sha512).hexdigest().encode('latin-1')
        
        if not hmac_matches(sent_hmac_sig, received_hmac_sig):
            logger.warning("FAILED: Attempt to upload failed on bad hmac. uuid: %s"%uuid)
            return FileUploadFailureResponse()
        
        write_img(cache_fp, img)
        image_fp = os.path.join(settings.IMAGE_FOLDER, uuid + '.tiff')
        convert_img_to_pyramid_tiff(cache_fp, image_fp)
        
        logger.info("Upload Complete. uuid: %s"%uuid)
        
        return Response(uuid+'.tiff')
    
def convert_img_to_pyramid_tiff(cache_fp,out_fp):
    params = ['convert',cache_fp,'-define','tiff:tile-geometry=128x128','ptif:'+out_fp]
    output = subprocess.check_output(params)
    if len(output):
        logger.warning('Problem with image conversion to ptif. Deleting files')
        if os.path.exists(out_fp):
            os.remove(out_fp)
    if os.path.exists(cache_fp):
        os.remove(cache_fp)
    
def write_img(fp, img):
    with open(fp, 'wb+') as destination:
        for chunk in img.chunks():
            destination.write(chunk)
            
def get_md5(img):
    hash_md5 = hashlib.md5()
    return hashlib.md5(img.read()).hexdigest()
    
def hmac_matches(hmac_1, hmac_2):
    return hmac.compare_digest(hmac_1,hmac_2) 
    
class FileUploadFailureResponse(Response):
    def __init__(self):
        message = "File failed to upload properly. Perhaps the connection cut out. Please try again."
        status = 222
        super(FileUploadFailureResponse, self).__init__(message, status, 'text/plain')
        
class OldTimestampResponse(Response):
    def __init__(self, timestamp=None):
        message = "Timestamp too old, or not specified. Request ignored."%timestamp
        status = 111
        super(OldTimestampResponse, self).__init__(message, status, 'text/plain')
        
class BadImageFormatResponse(Response):
    def __init__(self, fmt=None):
        message = "Image format %s not valid. Valid formats are: %s"%(fmt, settings.IMAGE_FORMATS)
        status = 333
        super(BadImageFormatResponse, self).__init__(message, status, 'text/plain')
        
def is_old_timestamp(timestamp):
    current = datetime.datetime.utcnow()
    timestamp = datetime.datetime.strptime(timestamp,'%Y-%m-%d %H:%M:%S.%f')
    threshold = datetime.timedelta(hours=1)
    return timestamp - current > threshold

def make_uuid():
    uuid = str(uuid4())
    fn = uuid + '.tiff'
    fp = os.path.join(settings.IMAGE_FOLDER,fn)
    while os.path.exists(fp):
        uuid = str(uuid4())
        fn = uuid + '.tiff'
    return uuid

def make_filename(fmt):
    fn = str(uuid4()) + '.' + fmt
    fp = os.path.join(settings.IMAGE_FOLDER,fn)
    while os.path.exists(fp):
        fn = str(uuid4()) + '.' + fmt
        fp = os.path.join(settings.IMAGE_FOLDER,fn)
    return fn

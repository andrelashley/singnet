import logging
import functools
import asyncio

import base64
import uuid
import python_digest
import time
from sn_agent.ui.settings import WebSettings

import aiohttp_jinja2 as aiohttp_jinja2
from aiohttp import web

logger = logging.getLogger(__name__)

def check_auth():
    def wrapper(f):
        @asyncio.coroutine
        @functools.wraps(f)
        def wrapped(self):
            settings = WebSettings()
            response = web.Response(text='')

            realm = settings.AUTH_REALM
            secret = settings.AUTH_SECRET
            rand_str = uuid.uuid4().hex[:6].upper()

            www_authenticate_header = python_digest.build_digest_challenge(time.time(), secret, realm, rand_str, False)

            if 'Authorization' in self.request.headers:
                auth_header = self.request.headers['Authorization']
                digest_response = python_digest.parse_digest_credentials(auth_header)

                # check for a valid nonce
                if python_digest.validate_nonce(digest_response.nonce, secret) == False:
                    response.headers['WWW-Authenticate'] = www_authenticate_header
                    response.set_status(401, "Invalid nonce!")
                    return response

                # check validity of auth response
                expected_request_digest = python_digest.calculate_request_digest(self.request.method, python_digest.calculate_partial_digest(settings.AUTH_USERNAME, settings.AUTH_REALM, settings.AUTH_PASSWORD), digest_response)
                if expected_request_digest != digest_response.response:
                    response.headers['WWW-Authenticate'] = www_authenticate_header
                    response.set_status(401, "Incorrect credentials!")
                    return response

                # if we're authenticated, proceed with the request
                return (yield from f(self))

            response.headers['WWW-Authenticate'] = www_authenticate_header
            response.set_status(401, "Login required!")
            return response
        return wrapped
    return wrapper


def get_base_context(app):
    context = {}
    context['service_adapters'] = app['service_manager'].service_adapters
    return context


class IndexHandler(web.View):
    @check_auth()
    async def get(self):

        context = get_base_context(self.request.app)
        response = aiohttp_jinja2.render_template('dashboard.jinja2', self.request, context)

        return response


class ServiceHandler(web.View):
    @check_auth()
    async def get(self):
        service_id = self.request.match_info.get('service_id')

        context = get_base_context(self.request.app)

        service_adapter = self.request.app['service_manager'].get_service_adapter_for_id(service_id)

        context['service_adapter'] = service_adapter

        context['page_title'] = service_adapter.service.name
        context['description'] = service_adapter.service.description

        response = aiohttp_jinja2.render_template('service-default.jinja2', self.request, context)
        return response


@aiohttp_jinja2.template('mnistclassifier.jinja2')
def tensorflowmnistclassifier(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}


@aiohttp_jinja2.template('simpleadapter.jinja2')
def simpleadapter(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}


@aiohttp_jinja2.template('relexparser.jinja2')
def relexparser(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}


@aiohttp_jinja2.template('aigentstextsclusterer.jinja2')
def aigentstextsclusterer(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}


@aiohttp_jinja2.template('aigentstextextractor.jinja2')
def aigentstextextractor(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}


@aiohttp_jinja2.template('aigentssocialgrapher.jinja2')
def aigentssocialgrapher(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}


@aiohttp_jinja2.template('aigentsrssfeeder.jinja2')
def aigentsrssfeeder(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}


@aiohttp_jinja2.template('tensorflowimagenetclassifier.jinja2')
def tensorflowimagenetclassifier(request):
    return {'name': 'Andrew', 'surname': 'Svetlov'}

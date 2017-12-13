import asyncio
import logging

import base64
import uuid
import python_digest
import time

import uvloop
from aiohttp import web
from aiohttp.web import middleware

from sn_agent.accounting import setup_accounting
from sn_agent.agent import setup_agent
from sn_agent.api import setup_api
from sn_agent.log import setup_logging
from sn_agent.network import setup_network
from sn_agent.ontology import setup_ontology
from sn_agent.routes import setup_routes

from sn_agent.service_adapter import setup_service_manager
from sn_agent.ui import setup_ui

logger = logging.getLogger(__name__)


async def startup(app):
    await app['network'].startup()

# @middleware
# async def middleware(request, handler):
#
#     resp = await handler(request)
#
#     realm = 'SingularityNET'
#
#     secret = 'b_wy%h=ts0ii3g0ulqbx8q%w(72zh%4hslu7js&(^q+_s49jj-'
#
#     rand_str = uuid.uuid4().hex[:6].upper()
#
#     www_authenticate_header = python_digest.build_digest_challenge(time.time(), secret, realm, rand_str, False)
#
#     if 'Authorization' in request.headers:
#         auth_header = request.headers['Authorization']
#         digest_response = python_digest.parse_digest_credentials(auth_header)
#
#         if python_digest.validate_nonce(digest_response.nonce, secret) == False:
#             resp.headers['WWW-Authenticate'] = www_authenticate_header
#             resp.set_status(401, "Invalid nonce!")
#
#         expected_request_digest = python_digest.calculate_request_digest(request.method, python_digest.calculate_partial_digest('bob', realm, '1234'), digest_response)
#
#         if expected_request_digest != digest_response.response:
#             resp.headers['WWW-Authenticate'] = www_authenticate_header
#             resp.set_status(401, "Incorrect credentials!")
#     else:
#         resp.headers['WWW-Authenticate'] = www_authenticate_header
#         resp.set_status(401, "Login required!")
#
#     return resp

def create_app():
    # Significant performance improvement: https://github.com/MagicStack/uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    app = web.Application()
    setup_logging()

    setup_ontology(app)
    setup_network(app)
    setup_service_manager(app)
    setup_accounting(app)
    setup_api(app)
    setup_agent(app)
    setup_routes(app)
    setup_ui(app)

    app['name'] = 'SingularityNET Agent'

    app.on_startup.append(startup)

    return app

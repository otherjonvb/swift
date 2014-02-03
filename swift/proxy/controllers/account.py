# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from swift import gettext_ as _
from urllib import unquote

from swift.account.utils import account_listing_response
from swift.common.request_helpers import get_listing_content_type
from swift.common.middleware.acl import parse_acl, format_acl
from swift.common.utils import public
from swift.common.constraints import check_metadata, MAX_ACCOUNT_NAME_LENGTH
from swift.common.http import HTTP_NOT_FOUND, HTTP_GONE
from swift.proxy.controllers.base import Controller, clear_info_cache
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.request_helpers import get_sys_meta_prefix


class AccountController(Controller):
    """WSGI controller for account requests"""
    server_type = 'Account'

    def __init__(self, app, account_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        if not self.app.allow_account_management:
            self.allowed_methods.remove('PUT')
            self.allowed_methods.remove('DELETE')

    def check_for_bad_account_acls(self, req):
        """
        Ensure that no bad-citizen auth middleware put garbage (non-JSON)
        account ACLs in sysmeta.  Strip the sysmeta if they did.
        :returns: None if the account ACL was valid (or didn't exist)
        :returns: HTTPBadRequest
        """
        inthdr = get_sys_meta_prefix('account') + 'core-access-control'
        acl_data = req.headers.get(inthdr)
        if acl_data:
            acl_dict = parse_acl(version=2, data=acl_data)
            if not acl_dict and acl_data != '{}':
                # JSON parse error -- invalid ACL
                del req.headers[inthdr]
                msg = ('Invalid account ACL: %r\nPossible faulty auth system?'
                       % acl_data)
                return HTTPBadRequest(request=req, body=msg)

    def GETorHEAD(self, req):
        """Handler for HTTP GET/HEAD requests."""
        if len(self.account_name) > MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name), MAX_ACCOUNT_NAME_LENGTH)
            return resp

        partition, nodes = self.app.account_ring.get_nodes(self.account_name)
        resp = self.GETorHEAD_base(
            req, _('Account'), self.app.account_ring, partition,
            req.swift_entity_path.rstrip('/'))
        if resp.status_int == HTTP_NOT_FOUND:
            if resp.headers.get('X-Account-Status', '').lower() == 'deleted':
                resp.status = HTTP_GONE
            elif self.app.account_autocreate:
                resp = account_listing_response(self.account_name, req,
                                                get_listing_content_type(req))
        if req.environ.get('swift_owner'):
            # Include X-Account-Access-Control header in response
            exthdr = 'x-account-access-control'
            inthdr = get_sys_meta_prefix('account') + 'core-access-control'
            acl_dict = parse_acl(version=2, data=resp.headers.pop(inthdr))
            if acl_dict:  # ignore empty dict as empty header
                resp.headers[exthdr] = format_acl(version=2, acl_dict=acl_dict)
        else:
            for hdr in self.app.swift_owner_headers:
                resp.headers.pop(hdr, None)
        return resp

    @public
    def PUT(self, req):
        """HTTP PUT request handler."""
        if not self.app.allow_account_management:
            return HTTPMethodNotAllowed(
                request=req,
                headers={'Allow': ', '.join(self.allowed_methods)})
        error_response = check_metadata(req, 'account')
        if error_response:
            return error_response
        if len(self.account_name) > MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name), MAX_ACCOUNT_NAME_LENGTH)
            return resp
        account_partition, accounts = \
            self.app.account_ring.get_nodes(self.account_name)
        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.check_for_bad_account_acls(req) or self.make_requests(
            req, self.app.account_ring, account_partition, 'PUT',
            req.swift_entity_path, [headers] * len(accounts))
        return resp

    @public
    def POST(self, req):
        """HTTP POST request handler."""
        if len(self.account_name) > MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Account name length of %d longer than %d' % \
                        (len(self.account_name), MAX_ACCOUNT_NAME_LENGTH)
            return resp
        error_response = check_metadata(req, 'account')
        if error_response:
            return error_response
        account_partition, accounts = \
            self.app.account_ring.get_nodes(self.account_name)
        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.check_for_bad_account_acls(req) or self.make_requests(
            req, self.app.account_ring, account_partition, 'POST',
            req.swift_entity_path, [headers] * len(accounts))
        if resp.status_int == HTTP_NOT_FOUND and self.app.account_autocreate:
            self.autocreate_account(req.environ, self.account_name)
            resp = self.make_requests(
                req, self.app.account_ring, account_partition, 'POST',
                req.swift_entity_path, [headers] * len(accounts))
        return resp

    @public
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        # Extra safety in case someone typos a query string for an
        # account-level DELETE request that was really meant to be caught by
        # some middleware.
        if req.query_string:
            return HTTPBadRequest(request=req)
        if not self.app.allow_account_management:
            return HTTPMethodNotAllowed(
                request=req,
                headers={'Allow': ', '.join(self.allowed_methods)})
        account_partition, accounts = \
            self.app.account_ring.get_nodes(self.account_name)
        headers = self.generate_request_headers(req)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.make_requests(
            req, self.app.account_ring, account_partition, 'DELETE',
            req.swift_entity_path, [headers] * len(accounts))
        return resp

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

from swift.common.utils import urlparse, json


def clean_acl(name, value):
    """
    Returns a cleaned ACL header value, validating that it meets the formatting
    requirements for standard Swift ACL strings.

    The ACL format is::

        [item[,item...]]

    Each item can be a group name to give access to or a referrer designation
    to grant or deny based on the HTTP Referer header.

    The referrer designation format is::

        .r:[-]value

    The ``.r`` can also be ``.ref``, ``.referer``, or ``.referrer``; though it
    will be shortened to just ``.r`` for decreased character count usage.

    The value can be ``*`` to specify any referrer host is allowed access, a
    specific host name like ``www.example.com``, or if it has a leading period
    ``.`` or leading ``*.`` it is a domain name specification, like
    ``.example.com`` or ``*.example.com``. The leading minus sign ``-``
    indicates referrer hosts that should be denied access.

    Referrer access is applied in the order they are specified. For example,
    .r:.example.com,.r:-thief.example.com would allow all hosts ending with
    .example.com except for the specific host thief.example.com.

    Example valid ACLs::

        .r:*
        .r:*,.r:-.thief.com
        .r:*,.r:.example.com,.r:-thief.example.com
        .r:*,.r:-.thief.com,bobs_account,sues_account:sue
        bobs_account,sues_account:sue

    Example invalid ACLs::

        .r:
        .r:-

    By default, allowing read access via .r will not allow listing objects in
    the container -- just retrieving objects from the container. To turn on
    listings, use the .rlistings directive.

    Also, .r designations aren't allowed in headers whose names include the
    word 'write'.

    ACLs that are "messy" will be cleaned up. Examples:

    ======================  ======================
    Original                Cleaned
    ----------------------  ----------------------
    ``bob, sue``            ``bob,sue``
    ``bob , sue``           ``bob,sue``
    ``bob,,,sue``           ``bob,sue``
    ``.referrer : *``       ``.r:*``
    ``.ref:*.example.com``  ``.r:.example.com``
    ``.r:*, .rlistings``    ``.r:*,.rlistings``
    ======================  ======================

    :param name: The name of the header being cleaned, such as X-Container-Read
                 or X-Container-Write.
    :param value: The value of the header being cleaned.
    :returns: The value, cleaned of extraneous formatting.
    :raises ValueError: If the value does not meet the ACL formatting
                        requirements; the error message will indicate why.
    """
    name = name.lower()
    values = []
    for raw_value in value.split(','):
        raw_value = raw_value.strip()
        if not raw_value:
            continue
        if ':' not in raw_value:
            values.append(raw_value)
            continue
        first, second = (v.strip() for v in raw_value.split(':', 1))
        if not first or first[0] != '.':
            values.append(raw_value)
        elif first in ('.r', '.ref', '.referer', '.referrer'):
            if 'write' in name:
                raise ValueError('Referrers not allowed in write ACL: '
                                 '%s' % repr(raw_value))
            negate = False
            if second and second[0] == '-':
                negate = True
                second = second[1:].strip()
            if second and second != '*' and second[0] == '*':
                second = second[1:].strip()
            if not second or second == '.':
                raise ValueError('No host/domain value after referrer '
                                 'designation in ACL: %s' % repr(raw_value))
            values.append('.r:%s%s' % ('-' if negate else '', second))
        else:
            raise ValueError('Unknown designator %s in ACL: %s' %
                             (repr(first), repr(raw_value)))
    return ','.join(values)


def format_acl_v1(groups=None, referrers=None, header_name=None):
    """
    Returns a standard Swift ACL string for the given inputs.

    Caller is responsible for ensuring that :referrers: parameter is only given
    if the ACL is being generated for X-Container-Read.  (X-Container-Write
    and the account ACL headers don't support referrers.)

    :param groups: a list of groups (and/or members in most auth systems) to
                   grant access
    :param referrers: a list of referrer designations (without the leading .r:)
    :param header_name: (optional) header name of the ACL we're preparing, for
                        clean_acl; if None, returned ACL won't be cleaned
    :returns: a Swift ACL string for use in X-Container-{Read,Write},
              X-Account-Access-Control, etc.
    """
    groups, referrers = groups or [], referrers or []
    referrers = ['.r:%s' % r for r in referrers]
    result = ','.join(groups + referrers)
    return (clean_acl(header_name, result) if header_name else result)


def format_acl_v2(acl_dict):
    """
    Returns a version-2 Swift ACL JSON string.

    HTTP headers for Version 2 ACLs have the following form:
      Header-Name: {"arbitrary":"json","encoded":"string"}

    JSON will be forced ASCII (containing six-char \uNNNN sequences rather
    than UTF-8; UTF-8 is valid JSON but clients vary in their support for
    UTF-8 headers), and without extraneous whitespace.

    Advantages over V1: forward compatibility (new keys don't cause parsing
    exceptions); Unicode support; no reserved words (you can have a user
    named .rlistings if you want).

    :param acl_dict: dict of arbitrary data to put in the ACL; see specific
                     auth systems such as tempauth for supported values
    :returns: a JSON string which encodes the ACL
    """
    return json.dumps(acl_dict, ensure_ascii=True, separators=(',', ':'),
                      sort_keys=True)


def format_acl(version=1, **kwargs):
    """
    Compatibility wrapper to help migrate ACL syntax from version 1 to 2.
    Delegates to the appropriate version-specific format_acl method, defaulting
    to version 1 for backward compatibility.

    :param kwargs: keyword args appropriate for the selected ACL syntax version
                   (see :func:`format_acl_v1` or :func:`format_acl_v2`)
    """
    if version == 1:
        return format_acl_v1(
            groups=kwargs.get('groups'), referrers=kwargs.get('referrers'),
            header_name=kwargs.get('header_name'))
    elif version == 2:
        return format_acl_v2(kwargs.get('acl_dict'))
    raise ValueError("Invalid ACL version: %r" % version)


def parse_acl_v1(acl_string):
    """
    Parses a standard Swift ACL string into a referrers list and groups list.

    See :func:`clean_acl` for documentation of the standard Swift ACL format.

    :param acl_string: The standard Swift ACL string to parse.
    :returns: A tuple of (referrers, groups) where referrers is a list of
              referrer designations (without the leading .r:) and groups is a
              list of groups to allow access.
    """
    referrers = []
    groups = []
    if acl_string:
        for value in acl_string.split(','):
            if value.startswith('.r:'):
                referrers.append(value[len('.r:'):])
            else:
                groups.append(value)
    return referrers, groups


def parse_acl_v2(data):
    """
    Parses a version-2 Swift ACL string and returns a dict of ACL info.

    :param data: string containing the ACL data in JSON format
    :returns: A dict containing ACL info, e.g.:
              {"groups": [...], "referrers": [...]}
    :returns: None if data is None
    :returns: empty dictionary if data does not parse as valid JSON
    """
    if data is None:
        return None
    try:
        return json.loads(data)
    except ValueError:
        return {}


def parse_acl(*args, **kwargs):
    """
    Compatibility wrapper to help migrate ACL syntax from version 1 to 2.
    Delegates to the appropriate version-specific parse_acl method, attempting
    to determine the version from the types of args/kwargs.

    :param args: positional args for the selected ACL syntax version
    :param kwargs: keyword args for the selected ACL syntax version
                   (see :func:`parse_acl_v1` or :func:`parse_acl_v2`)
    :returns: the return value of :func:`parse_acl_v1` or :func:`parse_acl_v2`
    """
    version = kwargs.pop('version', None)
    if version in (1, None):
        return parse_acl_v1(*args)
    elif version == 2:
        return parse_acl_v2(*args, **kwargs)
    else:
        raise ValueError('Unknown ACL version: parse_acl(%r, %r)' %
                         (args, kwargs))


def referrer_allowed(referrer, referrer_acl):
    """
    Returns True if the referrer should be allowed based on the referrer_acl
    list (as returned by :func:`parse_acl`).

    See :func:`clean_acl` for documentation of the standard Swift ACL format.

    :param referrer: The value of the HTTP Referer header.
    :param referrer_acl: The list of referrer designations as returned by
                         :func:`parse_acl`.
    :returns: True if the referrer should be allowed; False if not.
    """
    allow = False
    if referrer_acl:
        rhost = urlparse(referrer or '').hostname or 'unknown'
        for mhost in referrer_acl:
            if mhost[0] == '-':
                mhost = mhost[1:]
                if mhost == rhost or (mhost[0] == '.' and
                                      rhost.endswith(mhost)):
                    allow = False
            elif mhost == '*' or mhost == rhost or \
                    (mhost[0] == '.' and rhost.endswith(mhost)):
                allow = True
    return allow


def acls_from_account_info(info):
    """
    Extract the account ACLs from the given account_info, and return the ACLs.
    Account ACLs are assumed to be in TempAuth-style format.

    :param info: a dict of the form returned by get_account_info
    :returns: None (no ACL system metadata is set), or a dict of the form::
       {'admin': [...], 'read-write': [...], 'read-only': [...]}

    :raises ValueError: if a syntactically invalid ACL has somehow been
       persisted to the account info (impossible under normal circumstances)
    """
    data = info.get('sysmeta', {}).get('core-access-control')
    if data is None:
        return None
    acl_dict = parse_acl(version=2, data=data)
    return dict_to_tempauth_acl(acl_dict)


def acls_from_request_headers(req):
    """
    Extract the account ACLs from the request's headers, and return the ACLs.
    Account ACLs are assumed to be in TempAuth-style format.

    :param req: a swob.Request (or similar object with a dict-like 'headers'
       instance variable) containing the request headers
    :returns: None (no ACLs in the request headers), or a dict of the form::
       {'admin': [...], 'read-write': [...], 'read-only': [...]}

    :raises ValueError: on a syntactically invalid header
    """
    data = req.headers.get('X-Account-Access-Control')
    if data is None:
        return None
    acl_dict = parse_acl(version=2, data=data)
    if not (acl_dict or data in ('', '{}')):
        # parse_acl returned nothing but data wasn't empty -- json error
        raise ValueError('Syntax error in ACL (%r)' % data)
    return dict_to_tempauth_acl(acl_dict)


def dict_to_tempauth_acl(input_dict):
    """
    Validate and canonicalize input_dict as a TempAuth-style account ACL.

    :param input_dict: a dict containing a TempAuth-style account ACL
    :returns: None for empty input (input was None or {})
    :returns: input_dict if it was a valid TempAuth-style account ACL of the
       form::
       {'admin': [...], 'read-write': [...], 'read-only': [...]}
    :raises ValueError: if input_dict contains any invalid keys
    :raises ValueError: if input_dict contains valid TempAuth ACL keys but
       those keys don't map to valid values
    """
    if not input_dict:
        return None
    acl_dict = {}
    access_classes = 'admin read-write read-only'.split()
    for access_class in access_classes:
        members = input_dict.get(access_class, [])
        if not isinstance(members, list):
            raise ValueError('Value of %r (%r) must be a list' %
                             (access_class, members))
        acl_dict[access_class] = members
    bad_keys = [key for key in input_dict.keys() if key not in access_classes]
    if bad_keys:
        raise ValueError('Unknown access class: %s' % ', '.join(bad_keys))
    return acl_dict

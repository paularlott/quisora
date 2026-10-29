"""
quisora module

A client for the Quisora management API (/api/...).

It authenticates with a personal API token that has the admin scope, or with a
service account's client id and secret (the client credentials grant: an
access token is fetched, and fetched again shortly before it expires).

    import quisora

    qs = quisora.from_env()
    for user in qs.iter_users("acme", q="al"):
        print(user["username"], user["email"])

Organizations are named by their name or id. Lists answer
{"items": [...], "total": n}; the iter_* functions walk every page.
Any call the helpers do not cover is reachable through request().

An error answer raises QuisoraError, with the HTTP status, the server's
message and, when the error is about one input, the field it names.
"""

import json
import os
import time
import urllib.parse
import requests

API_VERSION = "2026-10-20"
MAX_PAGE = 100


class QuisoraError(Exception):
    """An error answered by Quisora (status 0: the server could not be reached)."""

    def __init__(self, status, message, field=None):
        self.status = status
        self.message = message
        self.field = field

    def __str__(self):
        if self.field:
            return f"{self.status}: {self.message} ({self.field})"
        return f"{self.status}: {self.message}"


def _seg(value):
    """Escape one path segment."""
    return urllib.parse.quote(str(value)).replace("/", "%2F")


def _flag(value):
    """A boolean query filter as the API takes it."""
    return "1" if value else "0"


def _drop_none(d):
    return {k: v for k, v in d.items() if v is not None}


_METHODS = {"GET": requests.get, "POST": requests.post, "PUT": requests.put,
            "PATCH": requests.patch, "DELETE": requests.delete}


def _send(method, url, **kwargs):
    """One HTTP request; a server that cannot be reached raises QuisoraError (status 0)."""
    if method not in _METHODS:
        raise QuisoraError(0, "unsupported method " + method)
    try:
        return _METHODS[method](url, **kwargs)
    except Exception as e:
        raise QuisoraError(0, str(e))


def _error(resp):
    try:
        body = resp.json()
        # the management API answers {"error", "field"}; the token endpoint {"error", "error_description"}
        message = body.get("error_description") or body.get("error") or resp.text
        return QuisoraError(resp.status_code, message, body.get("field"))
    except Exception:
        return QuisoraError(resp.status_code, resp.text.strip() or "HTTP " + str(resp.status_code))


class Client:
    """A connection to one Quisora server.

    url: the server's public URL, e.g. https://id.example.com
    token: a personal API token (qsr_...) with the admin scope
    client_id, client_secret, org: a service account, and the name or id of its
        organization (or token_endpoint, the one its creation answered)
    scope: for a service account, the scopes to ask for (default: all it holds)
    """

    def __init__(self, url, token=None, client_id=None, client_secret=None, org=None,
                 token_endpoint=None, scope=None, api_version=API_VERSION, timeout=30):
        self.url = url.rstrip("/")
        self.token = token
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.api_version = api_version
        self.timeout = timeout
        self.token_endpoint = token_endpoint
        if not self.token_endpoint and org:
            self.token_endpoint = self.url + "/o/" + _seg(org) + "/oauth/token"
        self._expires = 0
        if not token and not (client_id and client_secret and self.token_endpoint):
            raise QuisoraError(0, "a token, or a service account's client_id, client_secret and org, is needed")

    # --- plumbing -------------------------------------------------------

    def _bearer(self):
        if self.client_id and (not self.token or time.time() > self._expires - 30):
            form = {"grant_type": "client_credentials", "client_id": self.client_id,
                    "client_secret": self.client_secret}
            if self.scope:
                form["scope"] = self.scope
            resp = _send("POST", self.token_endpoint, data=urllib.parse.urlencode(form),
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         timeout=self.timeout)
            if resp.status_code != 200:
                raise _error(resp)
            body = resp.json()
            self.token = body["access_token"]
            self._expires = time.time() + body.get("expires_in", 600)
        return self.token

    def request(self, method, path, params=None, body=None):
        """Call the API: path is relative to the server (/api/...). Returns the
        decoded JSON answer, or None for an empty one."""
        headers = {"Authorization": "Bearer " + self._bearer(), "Api-Version": self.api_version,
                   "Accept": "application/json"}
        kwargs = {"headers": headers, "timeout": self.timeout}
        if params:
            kwargs["params"] = _drop_none(params)
        if body is not None:
            kwargs["data"] = json.dumps(body)
            headers["Content-Type"] = "application/json"
        resp = _send(method.upper(), self.url + path, **kwargs)
        if resp.status_code < 200 or resp.status_code >= 300:
            raise _error(resp)
        if not resp.text.strip():
            return None
        return resp.json()

    def paginate(self, path, params=None, page_size=MAX_PAGE):
        """Yield every item of a list endpoint, page by page."""
        params = dict(params or {})
        params["limit"] = page_size
        params["offset"] = params.get("offset") or 0
        items, i, total = [], 0, None
        # one flat loop: scriptling wants a generator's yield at the top level of its loop
        while True:
            if i == len(items):
                if total is not None and params["offset"] >= total:
                    return
                page = self.request("GET", path, params=params)
                items, i, total = page.get("items") or [], 0, page.get("total", 0)
                if not items:
                    return
                params["offset"] += len(items)
            yield items[i]
            i += 1

    def _org(self, org):
        return "/api/orgs/" + _seg(org)

    # --- organizations --------------------------------------------------

    def list_orgs(self, q=None, sort=None, desc=False, offset=0, limit=25):
        """One page of organizations (a super admin's token sees them all)."""
        return self.request("GET", "/api/orgs", params={"q": q, "sort": sort, "desc": "1" if desc else None,
                                                        "offset": offset, "limit": limit})

    def iter_orgs(self, q=None, sort=None, desc=False):
        return self.paginate("/api/orgs", {"q": q, "sort": sort, "desc": "1" if desc else None})

    def get_org(self, org):
        return self.request("GET", self._org(org))

    def create_org(self, name, display_name=None, settings=None, service_account=None):
        """Create an organization (super admin, or a service account with orgs:create).
        service_account, e.g. {"name": "setup", "scopes": ["users", "groups"]}, makes
        its first service account: the answer carries its secret, shown once."""
        return self.request("POST", "/api/orgs", body=_drop_none({
            "name": name, "display_name": display_name, "settings": settings,
            "service_account": service_account}))

    def update_org(self, org, **fields):
        """Change name, display_name or settings."""
        return self.request("PATCH", self._org(org), body=fields)

    def delete_org(self, org, cascade=False):
        """Delete an organization; cascade also deletes everything in it."""
        return self.request("DELETE", self._org(org), params={"cascade": "1" if cascade else None})

    # --- users ----------------------------------------------------------

    def _user_filters(self, q, role, active, tag, sort, desc):
        return {"q": q, "role": role, "active": None if active is None else _flag(active),
                "tag": tag, "sort": sort, "desc": "1" if desc else None}

    def list_users(self, org, q=None, role=None, active=None, tag=None, sort=None, desc=False,
                   offset=0, limit=25):
        """One page of users: {"items": [...], "total": n}. q is a prefix of a
        username, email address, full name or family name (or a tag)."""
        params = self._user_filters(q, role, active, tag, sort, desc)
        params["offset"] = offset
        params["limit"] = limit
        return self.request("GET", self._org(org) + "/users", params=params)

    def iter_users(self, org, q=None, role=None, active=None, tag=None, sort=None, desc=False):
        """Every user that matches, across pages."""
        return self.paginate(self._org(org) + "/users", self._user_filters(q, role, active, tag, sort, desc))

    def get_user(self, org, user_id):
        """One user, with their groups."""
        return self.request("GET", self._org(org) + "/users/" + _seg(user_id))

    def find_user(self, org, login):
        """The user whose username or email address is exactly login, or None."""
        login = login.lower()
        for user in self.iter_users(org, q=login):
            if (user.get("username") or "").lower() == login or (user.get("email") or "").lower() == login:
                return user
        return None

    def create_user(self, org, email, given_name, invite=None, **fields):
        """Create a user without a password. Other fields: username, family_name,
        role ("user", "manager", "admin"), tags, active, email_verified, locale,
        zoneinfo, phone_number, external_id, ... invite={"email": True} also
        issues an invitation link (and mails it)."""
        body = dict(fields)
        body["email"] = email
        body["given_name"] = given_name
        if invite is not None:
            body["invite"] = invite
        return self.request("POST", self._org(org) + "/users", body=body)

    def update_user(self, org, user_id, **fields):
        """Change a user: only the fields given are changed."""
        return self.request("PATCH", self._org(org) + "/users/" + _seg(user_id), body=fields)

    def delete_user(self, org, user_id):
        return self.request("DELETE", self._org(org) + "/users/" + _seg(user_id))

    def invite_user(self, org, user_id, email=False):
        """Issue a new single-use invitation link (valid 7 days; earlier links stop
        working): {"url", "expires", "emailed"}. email=True also mails it."""
        return self.request("POST", self._org(org) + "/users/" + _seg(user_id) + "/invite", body={"email": email})

    def sign_out_user(self, org, user_id):
        """End every session and refresh grant of the user."""
        return self.request("DELETE", self._org(org) + "/users/" + _seg(user_id) + "/sessions")

    def lock_out_user(self, org, user_id):
        """Disable the user and remove every way they had to sign in."""
        return self.request("POST", self._org(org) + "/users/" + _seg(user_id) + "/lock-out")

    # --- groups ---------------------------------------------------------

    def list_groups(self, org, q=None, sort=None, desc=False, offset=0, limit=25):
        return self.request("GET", self._org(org) + "/groups", params={
            "q": q, "sort": sort, "desc": "1" if desc else None, "offset": offset, "limit": limit})

    def iter_groups(self, org, q=None, sort=None, desc=False):
        return self.paginate(self._org(org) + "/groups", {"q": q, "sort": sort, "desc": "1" if desc else None})

    def get_group(self, org, group_id):
        return self.request("GET", self._org(org) + "/groups/" + _seg(group_id))

    def create_group(self, org, display_name, tags=None, external_id=None):
        return self.request("POST", self._org(org) + "/groups", body=_drop_none({
            "display_name": display_name, "tags": tags, "external_id": external_id}))

    def update_group(self, org, group_id, **fields):
        return self.request("PATCH", self._org(org) + "/groups/" + _seg(group_id), body=fields)

    def delete_group(self, org, group_id):
        return self.request("DELETE", self._org(org) + "/groups/" + _seg(group_id))

    def iter_group_members(self, org, group_id):
        return self.paginate(self._org(org) + "/groups/" + _seg(group_id) + "/members")

    def add_group_member(self, org, group_id, user_id):
        """Add a user to a group (nothing changes if they are in it already)."""
        return self.request("PUT", self._org(org) + "/groups/" + _seg(group_id) + "/members/" + _seg(user_id))

    def remove_group_member(self, org, group_id, user_id):
        return self.request("DELETE", self._org(org) + "/groups/" + _seg(group_id) + "/members/" + _seg(user_id))

    # --- service accounts -----------------------------------------------

    def iter_service_accounts(self, org):
        return self.paginate(self._org(org) + "/service-accounts")

    def create_service_account(self, org, name, scopes, **fields):
        """Create a service account; the answer carries its id (client_id),
        token_endpoint and, shown once, its secret."""
        body = dict(fields)
        body["name"] = name
        body["scopes"] = scopes
        return self.request("POST", self._org(org) + "/service-accounts", body=body)

    def delete_service_account(self, org, account_id):
        return self.request("DELETE", self._org(org) + "/service-accounts/" + _seg(account_id))

    def rotate_service_account_secret(self, org, account_id):
        return self.request("POST", self._org(org) + "/service-accounts/" + _seg(account_id) + "/secret")

    # --- audit ----------------------------------------------------------

    def list_audit(self, org, offset=0, limit=25, **filters):
        """One page of the organization's audit events. filters: q, sort, desc,
        from, to, action, outcome, ... as in the OpenAPI document."""
        params = dict(filters)
        params["offset"] = offset
        params["limit"] = limit
        return self.request("GET", self._org(org) + "/audit", params=params)


def from_env():
    """A Client configured from the environment:

    QUISORA_URL            the server, e.g. https://id.example.com
    QUISORA_TOKEN          a personal API token with the admin scope, or
    QUISORA_CLIENT_ID      a service account's client id,
    QUISORA_CLIENT_SECRET  its secret, and
    QUISORA_ORG            its organization (or QUISORA_TOKEN_ENDPOINT)
    """
    url = os.environ.get("QUISORA_URL")
    if not url:
        raise QuisoraError(0, "QUISORA_URL is not set")
    return Client(url,
                  token=os.environ.get("QUISORA_TOKEN"),
                  client_id=os.environ.get("QUISORA_CLIENT_ID"),
                  client_secret=os.environ.get("QUISORA_CLIENT_SECRET"),
                  org=os.environ.get("QUISORA_ORG"),
                  token_endpoint=os.environ.get("QUISORA_TOKEN_ENDPOINT"))

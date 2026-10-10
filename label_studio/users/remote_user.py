"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.

Modified by B2Metric (Apache-2.0 section 4(b)): this file is new in the B2Metric fork.

Sign users in from the email header of a trusted authenticating reverse proxy (for example
oauth2-proxy behind an nginx ingress ``auth-url``). Opt-in: nothing here is loaded unless the
``REMOTE_USER_EMAIL_HEADER`` setting (env ``LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER``) is set.

Rules:

* Allowlist, not auto-provisioning. The header only matches an existing, active account. An
  unknown email gets no session and no account is created, because every Community account is
  an organization admin and could read everyone's data.
* A password session is never replaced by the header, and a request carrying an ``Authorization``
  header never opens a new header session. Only a session that was itself opened from the header
  follows it, and it is re-checked on every request: it ends when the header is gone, names someone
  else, or the account was deactivated, removed from the organization or became ambiguous. While
  all of that holds, the proxy's session decides how long the person stays in, not Label Studio's
  session age limits.
* The account must also be a current member of an organization. Removing a member from the
  organization does not deactivate the account, and an account that is still active but no longer
  a member would otherwise keep getting a session (and fall back to the first organization).
  Deactivating the account is the revocation that keeps its annotations.

What the deployment must guarantee (this module cannot check any of it):

* Only the proxy can reach Label Studio, and the proxy overwrites any client-supplied copy of the
  header. Otherwise anyone could claim any email. Mind the underscore spelling: a client header
  ``X_Auth_Request_Email`` lands under the same WSGI key as ``X-Auth-Request-Email``; the proxy has
  to drop such headers (ingress-nginx does by default) or the server has to (Django ``runserver``
  does, uwsgi does not).
* The identity provider hands out only verified, unique emails, and the proxy refuses the rest.
* Signing up is closed (``LABEL_STUDIO_DISABLE_SIGNUP_WITHOUT_LINK``) and SSO accounts carry no
  usable password, so nobody can pre-register a password for an address that is later allowlisted.
"""
import logging
import time

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.backends import RemoteUserBackend
from django.core.exceptions import ImproperlyConfigured
from django.utils.deprecation import MiddlewareMixin
from users.functions.common import login

logger = logging.getLogger(__name__)


def remote_user_meta_key():
    """``X-Auth-Request-Email`` -> ``HTTP_X_AUTH_REQUEST_EMAIL``, the key WSGI puts it under."""
    return 'HTTP_' + settings.REMOTE_USER_EMAIL_HEADER.upper().replace('-', '_')


class AllowlistRemoteUserBackend(RemoteUserBackend):
    """Resolve a proxy-supplied email to an existing active user; never create one."""

    create_unknown_user = False

    def authenticate(self, request, remote_user=None):
        email = (remote_user or '').strip()
        if not email:
            return None

        # Emails are stored as typed, the proxy's value is normalised; match without case.
        matches = list(auth.get_user_model()._default_manager.filter(email__iexact=email)[:2])
        if len(matches) != 1:
            if matches:
                logger.warning(
                    'Remote user email matches several accounts, refusing (user ids %s)', [u.pk for u in matches]
                )
            return None

        user = matches[0]
        if not self.user_can_authenticate(user):
            return None
        if not user.om_through.filter(deleted_at__isnull=True).exists():
            logger.info('Remote user %s is no member of any organization, refusing', user.pk)
            return None
        return user


class AllowlistRemoteUserMiddleware(MiddlewareMixin):
    """Open a session for the allowlisted user named by the proxy header.

    Must run after ``AuthenticationMiddleware``.
    """

    def process_request(self, request):
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                'AllowlistRemoteUserMiddleware needs AuthenticationMiddleware before it in MIDDLEWARE.'
            )

        email = (request.META.get(remote_user_meta_key()) or '').strip().lower()

        if request.user.is_authenticated:
            if not self._session_is_from_header(request):
                return  # password session: the header never replaces it
            # A running header session is held to the same rules as a new one on every request: the header
            # must still name this person and the account must still be active, unique and a member. Cookies
            # cannot be revoked server side, so this is what ends the session of a removed or deactivated user.
            if email and self._same_person(request, email):
                # The proxy vouches for this person on every request, so its session decides how long they stay
                # in. Keeping last_login fresh stops the inactivity middleware (it runs after this one) from
                # logging them out for one request when the Label Studio limits run out.
                request.session['last_login'] = time.time()
                return
            auth.logout(request)  # the proxy now names someone else or nobody, or the account lost its access

        if not email or request.META.get('HTTP_AUTHORIZATION'):
            return  # (a token or JWT request is its own thing: no new header session next to it)

        user = auth.authenticate(request, remote_user=email)
        if user is not None:
            if auth.SESSION_KEY in request.session:
                # a stale session of a deactivated or different user: login() would flush it and
                # lose the last_login stamp below, so start clean
                auth.logout(request)
            request.user = user
            # LS's own login(): also stamps session['last_login'], which the inactivity
            # timeout reads; with auth.login() alone that stamp is missing and the user is logged out again.
            login(request, user)

    @staticmethod
    def _same_person(request, email):
        user = AllowlistRemoteUserBackend().authenticate(request, remote_user=email)
        return user is not None and user.pk == request.user.pk

    @staticmethod
    def _session_is_from_header(request):
        try:
            backend = auth.load_backend(request.session.get(auth.BACKEND_SESSION_KEY, ''))
        except ImportError:
            return False
        return isinstance(backend, AllowlistRemoteUserBackend)

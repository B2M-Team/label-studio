"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.

Modified by B2Metric (Apache-2.0 section 4(b)): this file is new in the B2Metric fork.

Sign users in from the email header of a trusted authenticating reverse proxy (for example
oauth2-proxy behind an nginx ingress ``auth-url``). Opt-in: nothing here is loaded unless the
``REMOTE_USER_EMAIL_HEADER`` setting (env ``LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER``) is set.

Rules:

* Allowlist, not auto-provisioning. The header only matches an existing, active account. An
  unknown email gets no session and no account is created, because every Community account is
  an organization admin and could read everyone's data.
* A password or token session is never replaced by the header. Only a session that was itself
  opened from the header follows it: it switches when the header names someone else and ends
  when the header is gone.
* The deployment must make sure that only the proxy can reach Label Studio and that the proxy
  overwrites any client-supplied copy of the header. Otherwise anyone could claim any email.
"""
import logging

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
                logger.warning('Remote user email matches several accounts, refusing: %s', email)
            return None

        user = matches[0]
        return user if self.user_can_authenticate(user) else None


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
                return  # password or token session: the header never replaces it
            if request.user.email.lower() == email:
                return
            auth.logout(request)  # the proxy now names someone else, or nobody

        if not email:
            return

        user = auth.authenticate(request, remote_user=email)
        if user is not None:
            request.user = user
            # LS's own login(): also stamps session['last_login'], which the inactivity
            # timeout reads; auth.login() alone would log the user out on the next request.
            login(request, user)

    @staticmethod
    def _session_is_from_header(request):
        try:
            backend = auth.load_backend(request.session.get(auth.BACKEND_SESSION_KEY, ''))
        except ImportError:
            return False
        return isinstance(backend, AllowlistRemoteUserBackend)

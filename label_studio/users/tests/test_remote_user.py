"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.

Modified by B2Metric (Apache-2.0 section 4(b)): this file is new in the B2Metric fork.
"""
import json
import os
import subprocess
import sys
from unittest import mock

import pytest
from django.conf import settings
from django.test import Client, TestCase, override_settings
from organizations.tests.factories import OrganizationFactory
from users.functions.common import login
from users.models import User
from users.tests.factories import UserFactory

HEADER = 'X-Auth-Request-Email'
META = 'HTTP_X_AUTH_REQUEST_EMAIL'
WHOAMI = '/api/current-user/whoami'
PASSWORD = 'correct-horse-battery'  # noqa: S105 - throwaway test value


def _remote_user_settings():
    middleware = list(settings.MIDDLEWARE)
    at = middleware.index('django.contrib.auth.middleware.AuthenticationMiddleware') + 1
    middleware.insert(at, 'users.remote_user.AllowlistRemoteUserMiddleware')
    return {
        'MIDDLEWARE': middleware,
        'AUTHENTICATION_BACKENDS': [
            *settings.AUTHENTICATION_BACKENDS,
            'users.remote_user.AllowlistRemoteUserBackend',
        ],
        'REMOTE_USER_EMAIL_HEADER': HEADER,
    }


@override_settings(**_remote_user_settings())
class TestRemoteUserSignIn(TestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.analyst = UserFactory(email='Ana.Lyst@STC.com.kw', active_organization=self.organization)
        self.other = UserFactory(email='other@stc.com.kw', active_organization=self.organization)
        self.client = Client()

    def whoami(self, email=None, client=None):
        extra = {META: email} if email is not None else {}
        return (client or self.client).get(WHOAMI, **extra)

    def signed_in(self):
        return '_auth_user_id' in self.client.session

    def test_allowlisted_email_gets_a_session(self):
        response = self.whoami('ana.lyst@stc.com.kw')

        assert response.status_code == 200
        assert response.json()['email'] == self.analyst.email

    def test_session_follows_a_header_that_names_someone_else(self):
        self.whoami('ana.lyst@stc.com.kw')

        # same browser, header now names someone else: the session follows it
        response = self.whoami('other@stc.com.kw')

        assert response.json()['email'] == self.other.email

    def test_session_ends_when_the_header_is_gone(self):
        self.whoami('ana.lyst@stc.com.kw')

        assert self.whoami().status_code == 401

    def test_session_stamps_last_login_for_the_inactivity_timeout(self):
        self.whoami('ana.lyst@stc.com.kw')

        assert 'last_login' in self.client.session

    def test_unknown_email_gets_nothing_and_creates_nothing(self):
        before = User.objects.count()

        response = self.whoami('stranger@stc.com.kw')

        assert response.status_code == 401
        assert not self.signed_in()
        assert User.objects.count() == before

    def test_inactive_account_gets_nothing(self):
        self.analyst.is_active = False
        self.analyst.save(update_fields=['is_active'])

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 401
        assert not self.signed_in()

    def test_ambiguous_email_is_refused(self):
        UserFactory(email='ana.lyst@stc.com.kw', active_organization=self.organization)

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 401
        assert not self.signed_in()

    def test_removed_member_gets_nothing(self):
        # soft_delete() is what "Remove member" does: the account stays active, the membership goes
        self.analyst.om_through.get(organization=self.organization).soft_delete()

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 401
        assert not self.signed_in()

    def test_deactivated_user_loses_a_running_header_session(self):
        self.whoami('ana.lyst@stc.com.kw')
        self.analyst.is_active = False
        self.analyst.save(update_fields=['is_active'])

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 401

    def test_other_user_signs_in_over_the_stale_session_of_a_deactivated_one(self):
        self.whoami('ana.lyst@stc.com.kw')
        self.analyst.is_active = False
        self.analyst.save(update_fields=['is_active'])

        # same browser, the header now names an active user: signed in and the timeout stamp survives
        assert self.whoami('other@stc.com.kw').json()['email'] == self.other.email
        assert 'last_login' in self.client.session
        assert self.whoami('other@stc.com.kw').json()['email'] == self.other.email

    def test_session_ends_when_the_header_switches_to_an_unknown_email(self):
        self.whoami('ana.lyst@stc.com.kw')

        assert self.whoami('stranger@stc.com.kw').status_code == 401
        assert not self.signed_in()

    def test_mixed_case_account_signs_in_once_not_on_every_request(self):
        with mock.patch('users.remote_user.login', wraps=login) as signed_in:
            self.whoami('ana.lyst@stc.com.kw')
            self.whoami('ana.lyst@stc.com.kw')
            self.whoami('ana.lyst@stc.com.kw')

        assert signed_in.call_count == 1

    def test_session_does_not_bounce_when_the_labelstudio_limits_run_out(self):
        self.whoami('ana.lyst@stc.com.kw')
        stale = self.client.session
        stale['last_login'] = 0  # signed in long ago
        stale.save()
        # signed-cookie sessions live in the cookie: hand the aged one to the client
        self.client.cookies[settings.SESSION_COOKIE_NAME] = stale.session_key

        # the proxy still vouches for the person: no 401 for the request that finds the limits over
        assert self.whoami('ana.lyst@stc.com.kw').status_code == 200
        assert self.whoami('ana.lyst@stc.com.kw').status_code == 200

    def test_running_session_ends_when_the_member_is_removed(self):
        self.whoami('ana.lyst@stc.com.kw')
        self.analyst.om_through.get(organization=self.organization).soft_delete()

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 401
        assert not self.signed_in()

    def test_running_session_ends_when_the_account_is_deactivated(self):
        self.whoami('ana.lyst@stc.com.kw')
        self.analyst.is_active = False
        self.analyst.save(update_fields=['is_active'])

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 401

    def test_running_session_ends_when_the_email_turns_ambiguous(self):
        self.whoami('ana.lyst@stc.com.kw')
        UserFactory(email='ana.lyst@stc.com.kw', active_organization=self.organization)

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 401

    def test_authorization_header_does_not_keep_a_header_session_alive_for_another_person(self):
        self.whoami('ana.lyst@stc.com.kw')

        # same cookie, but the proxy now names someone else (and a bogus Authorization rides along)
        self.client.get(WHOAMI, HTTP_AUTHORIZATION='Basic eDp4', **{META: 'other@stc.com.kw'})

        assert not self.signed_in()

    def test_request_with_an_authorization_header_gets_no_header_session(self):
        response = self.client.get(WHOAMI, HTTP_AUTHORIZATION='Token not-a-real-token', **{META: 'ana.lyst@stc.com.kw'})

        assert response.status_code == 401
        assert not self.signed_in()

    def test_authorization_header_does_not_end_a_matching_header_session(self):
        self.whoami('ana.lyst@stc.com.kw')

        self.client.get(WHOAMI, HTTP_AUTHORIZATION='Basic eDp4', **{META: 'ana.lyst@stc.com.kw'})

        assert self.signed_in()

    def test_logout_does_not_stick_while_the_proxy_still_vouches(self):
        self.whoami('ana.lyst@stc.com.kw')

        self.client.get('/logout', **{META: 'ana.lyst@stc.com.kw'})

        assert self.whoami('ana.lyst@stc.com.kw').status_code == 200

    def test_blank_header_is_ignored(self):
        assert self.whoami('  ').status_code == 401

    def password_login(self, extra=None):
        """Sign in through the login page: LS's own login() stamps session['last_login'], client.login() does not."""
        self.other.set_password(PASSWORD)
        self.other.save()
        response = self.client.post('/user/login/', {'email': self.other.email, 'password': PASSWORD}, **(extra or {}))
        assert response.status_code == 302

    def test_password_session_is_never_replaced_by_the_header(self):
        self.password_login()

        response = self.whoami('ana.lyst@stc.com.kw')

        assert response.json()['email'] == self.other.email

    def test_password_session_survives_a_missing_header(self):
        self.password_login()

        assert self.whoami().json()['email'] == self.other.email

    def test_password_login_works_for_a_header_email_that_is_not_allowlisted(self):
        self.password_login(extra={META: 'maintainer@stc.com.kw'})

        assert self.whoami('maintainer@stc.com.kw').json()['email'] == self.other.email

    def test_allowlisted_header_email_is_signed_in_before_the_login_form(self):
        """Keep maintainers' own STC emails out of the allowlist, or they cannot reach the local admin login."""
        self.password_login(extra={META: 'ana.lyst@stc.com.kw'})

        assert self.whoami('ana.lyst@stc.com.kw').json()['email'] == self.analyst.email


PROJECTS = '/api/projects'
SEC_FETCH_SITE = 'HTTP_SEC_FETCH_SITE'


def password_login(client, user):
    """Sign in through the login page (LS's own login() stamps session['last_login'], force_login() does not and the
    inactivity timeout then logs the session out)."""
    user.set_password(PASSWORD)
    user.save()
    response = client.post('/user/login/', {'email': user.email, 'password': PASSWORD})
    assert response.status_code == 302


@override_settings(**_remote_user_settings())
class TestCrossSiteWrites(TestCase):
    """Label Studio switches CSRF off, and every host under the gate's registrable domain counts as the same *site*
    (SameSite=Lax cookies are sent), so a page on a sibling host could otherwise write as the signed-in analyst."""

    def setUp(self):
        self.organization = OrganizationFactory()
        self.analyst = UserFactory(email='ana.lyst@stc.com.kw', active_organization=self.organization)
        self.client = Client()

    def create_project(self, **extra):
        extra.setdefault(META, 'ana.lyst@stc.com.kw')
        return self.client.post(PROJECTS, data=json.dumps({'title': 'xsite probe'}), content_type='application/json', **extra)

    def projects(self):
        from projects.models import Project

        return Project.objects.count()

    def test_same_origin_write_works(self):
        response = self.create_project(**{SEC_FETCH_SITE: 'same-origin'})

        assert response.status_code == 201, response.content
        assert self.projects() == 1

    def test_write_from_another_site_or_sibling_host_is_refused(self):
        for site in ('same-site', 'cross-site', 'Same-Site'):
            with self.subTest(site=site):
                response = self.create_project(**{SEC_FETCH_SITE: site})

                assert response.status_code == 403
                assert self.projects() == 0

    def test_refused_write_opens_no_session(self):
        self.create_project(**{SEC_FETCH_SITE: 'same-site'})

        assert '_auth_user_id' not in self.client.session

    def test_refused_write_is_refused_for_a_running_header_session_too(self):
        self.client.get(WHOAMI, **{META: 'ana.lyst@stc.com.kw'})

        response = self.create_project(**{SEC_FETCH_SITE: 'same-site'})

        assert response.status_code == 403
        assert self.projects() == 0

    def test_user_initiated_navigation_is_allowed(self):
        assert self.create_project(**{SEC_FETCH_SITE: 'none'}).status_code == 201

    def test_without_sec_fetch_site_a_foreign_origin_is_refused(self):
        response = self.create_project(HTTP_ORIGIN='https://commbi.stc.com.kw')

        assert response.status_code == 403
        assert self.projects() == 0

    def test_without_sec_fetch_site_the_opaque_null_origin_is_refused(self):
        assert self.create_project(HTTP_ORIGIN='null').status_code == 403

    def test_without_sec_fetch_site_the_own_origin_is_allowed(self):
        assert self.create_project(HTTP_ORIGIN='http://testserver').status_code == 201

    def test_a_request_that_says_nothing_is_allowed(self):
        """curl, scripts, old clients: they cannot ride on a victim's cookies, so there is nothing to check."""
        assert self.create_project().status_code == 201

    def test_sec_fetch_site_wins_over_a_matching_origin(self):
        response = self.create_project(HTTP_ORIGIN='http://testserver', **{SEC_FETCH_SITE: 'same-site'})

        assert response.status_code == 403

    def test_reads_are_never_refused(self):
        for site in ('same-site', 'cross-site'):
            with self.subTest(site=site):
                response = self.client.get(WHOAMI, **{META: 'ana.lyst@stc.com.kw', SEC_FETCH_SITE: site})

                assert response.status_code == 200

    def test_token_requests_are_not_touched_by_the_check(self):
        """A foreign page cannot add an Authorization header without a preflight, which CORS refuses."""
        response = self.create_project(HTTP_AUTHORIZATION='Token not-a-token', **{SEC_FETCH_SITE: 'same-site'})

        assert response.status_code == 401
        assert self.projects() == 0

    def test_password_sessions_are_covered_too(self):
        password_login(self.client, self.analyst)

        response = self.client.post(
            PROJECTS, data=json.dumps({'title': 'xsite probe'}), content_type='application/json', **{SEC_FETCH_SITE: 'same-site'}
        )

        assert response.status_code == 403
        assert self.projects() == 0


class TestRemoteUserOffByDefault(TestCase):
    def test_not_wired_in_unless_the_setting_is_set(self):
        assert settings.REMOTE_USER_EMAIL_HEADER == ''
        assert 'users.remote_user.AllowlistRemoteUserMiddleware' not in settings.MIDDLEWARE
        assert 'users.remote_user.AllowlistRemoteUserBackend' not in settings.AUTHENTICATION_BACKENDS

    def test_cross_site_writes_are_not_checked_when_off(self):
        """Unset means upstream behaviour: the check lives in the remote-user middleware only."""
        organization = OrganizationFactory()
        user = UserFactory(email='ana.lyst@stc.com.kw', active_organization=organization)
        client = Client()
        password_login(client, user)

        response = client.post(
            PROJECTS, data=json.dumps({'title': 'xsite probe'}), content_type='application/json', **{SEC_FETCH_SITE: 'same-site'}
        )

        assert response.status_code == 201, response.content

    def test_header_does_nothing_when_off(self):
        organization = OrganizationFactory()
        UserFactory(email='ana.lyst@stc.com.kw', active_organization=organization)

        response = Client().get(WHOAMI, **{META: 'ana.lyst@stc.com.kw'})

        assert response.status_code == 401


@pytest.mark.parametrize(
    'header, key',
    [('X-Auth-Request-Email', 'HTTP_X_AUTH_REQUEST_EMAIL'), ('x-forwarded-email', 'HTTP_X_FORWARDED_EMAIL')],
)
def test_meta_key_for_header_name(header, key):
    from users.remote_user import remote_user_meta_key

    with override_settings(REMOTE_USER_EMAIL_HEADER=header):
        assert remote_user_meta_key() == key


def _settings_with_env(tmp_path, **env):
    """Load the real settings module in a fresh process: the override_settings above rebuild the wiring by hand."""
    code = (
        'import json; from django.conf import settings as s; '
        'print(json.dumps({"mw": "users.remote_user.AllowlistRemoteUserMiddleware" in s.MIDDLEWARE, '
        '"backend": "users.remote_user.AllowlistRemoteUserBackend" in s.AUTHENTICATION_BACKENDS, '
        '"header": s.REMOTE_USER_EMAIL_HEADER, "signup_closed": s.DISABLE_SIGNUP_WITHOUT_LINK}))'
    )
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(('LABEL_STUDIO_REMOTE_USER', 'LABEL_STUDIO_DISABLE_SIGNUP'))}
    child_env.update(
        DJANGO_SETTINGS_MODULE='core.settings.label_studio', LABEL_STUDIO_BASE_DATA_DIR=str(tmp_path), **env
    )
    out = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, '-c', code], cwd=os.path.dirname(settings.BASE_DIR), env=child_env, capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_real_settings_wire_everything_in_and_close_sign_up_when_the_header_is_set(tmp_path):
    loaded = _settings_with_env(tmp_path, LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER='X-Auth-Request-Email')

    assert loaded == {'mw': True, 'backend': True, 'header': 'X-Auth-Request-Email', 'signup_closed': True}


def test_real_settings_leave_sign_up_alone_when_the_header_is_off(tmp_path):
    loaded = _settings_with_env(tmp_path)

    assert loaded == {'mw': False, 'backend': False, 'header': '', 'signup_closed': False}


def test_real_settings_treat_a_blank_header_value_as_off(tmp_path):
    loaded = _settings_with_env(tmp_path, LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER='  ')

    assert loaded['mw'] is False and loaded['header'] == ''


def test_sign_up_can_still_be_opened_explicitly(tmp_path):
    loaded = _settings_with_env(
        tmp_path, LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER='X-Auth-Request-Email', LABEL_STUDIO_DISABLE_SIGNUP_WITHOUT_LINK='false'
    )

    assert loaded['signup_closed'] is False

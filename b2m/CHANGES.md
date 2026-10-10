# B2Metric changes to Label Studio

This fork tracks upstream release tags of [HumanSignal/label-studio](https://github.com/HumanSignal/label-studio)
(Apache License 2.0, see `LICENSE` and `NOTICE`). Per section 4(b) of the license, the files
changed from the upstream release are listed here; each carries its own notice.

Base: tag `1.23.2` (`df96d79`).

| File | Change |
| --- | --- |
| `label_studio/users/remote_user.py` | New. Sign in from the email header of a trusted authenticating reverse proxy, allowlist only. |
| `label_studio/core/settings/base.py` | When `LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER` (or `HEARTEX_` / bare `REMOTE_USER_EMAIL_HEADER`) is set, add the middleware and backend above, send `X-Frame-Options: SAMEORIGIN` (Django's `XFrameOptionsMiddleware`) and default `DISABLE_SIGNUP_WITHOUT_LINK` to true. Unset (the default) changes nothing. |
| `label_studio/users/tests/test_remote_user.py` | New. Tests for the above. |
| `b2m/` | New. Image build and this file. |

## Remote-user sign-in

Community has no SSO. This adds the smallest thing that lets a deployment behind oauth2-proxy
(nginx `auth-url`, which already authenticates against Keycloak) skip a second login.

* Set `LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER=X-Auth-Request-Email` (the header the proxy sets).
* The header must match an existing, active account (case-insensitive). Unknown emails get no
  session and **no account is created**: every Community account is an organization admin, so
  auto-creating everyone the proxy admits would expose all projects and annotations.
* The account must also be a current member of an organization. "Remove member" only soft-deletes the
  membership and leaves the account active, so an active account is not enough.
* A password session is never replaced by the header, and a request with an `Authorization` header gets
  no header session. A session opened from the header follows it: another email switches the user, no
  header ends the session. While the header keeps matching, the proxy's session decides how long the
  person stays in (Label Studio's own session age / idle limits are not applied to header sessions).
* **Revoking access** = deactivate the account (`is_active=False`); its annotations stay. SSO accounts
  have no password, so there is nothing else to take away. The header session ends on the next request.
* **Logout does not stick.** While the proxy still vouches for the person, the next request signs them
  in again.

What the deployment has to guarantee (the module cannot check it):

* Only the proxy can reach the app, and the proxy overwrites a client-supplied copy of the header.
  Without that, anyone can claim any email. A client header `X_Auth_Request_Email` (underscores) maps
  to the same WSGI key; ingress-nginx drops such headers by default and Django `runserver` strips
  them, uwsgi does not.
* The identity provider issues only verified, unique emails and the proxy refuses the rest.
* Signing up stays closed (the default with the header set; do not set
  `LABEL_STUDIO_DISABLE_SIGNUP_WITHOUT_LINK=false`) and SSO accounts have no usable password, so nobody
  can pre-register a password for an address that is allowlisted later.
* Do not put a maintainer's own proxy-authenticated email on the allowlist if they need the local
  password login: the header signs them in before the login form.
* Serve Label Studio from its own host if other people's apps share the origin: a script on a shared
  origin can call the API and gets the viewer's session without the viewer ever opening Label Studio
  (CSRF is disabled app-wide in Label Studio). The cross-site check below covers the sibling hosts.

## Cross-site writes are refused

Label Studio switches CSRF protection off (`DisableCSRF`), and a browser sends a `SameSite=Lax` session
cookie on a request from any page of the same *site*, which includes every sibling host under the same
registrable domain. Without a check, a page on such a host could make a blind write (a simple POST) as
the signed-in person. The middleware therefore answers 403, before any sign-in, to a state-changing
request (not GET/HEAD/OPTIONS/TRACE) unless:

* `Sec-Fetch-Site` is `same-origin` or `none` (a header page script cannot set; `same-site`,
  `cross-site` and unknown values are refused), or
* the browser sent no `Sec-Fetch-Site` and `Origin` is the request's own host (scheme is not compared;
  `Origin: null`, another port and anything unparsable are refused), or
* neither header is present (a command-line client or a token SDK, not a browser carrying someone's
  cookies: a conforming browser sends `Origin` on every unsafe request).

An `Authorization` header is not an exemption: a browser request that carries one is judged like any
other, so a proxy or browser that attaches one on its own cannot open a way around the check. The check
applies to every session on the instance, password sessions included, and only while
`LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER` is set.

**Framing.** The pod sends no `X-Frame-Options` and its CSP is report-only without `frame-ancestors`, so a
sibling host could frame Label Studio and steer the visitor's clicks; those requests are same-origin and
pass the check above. With the header set, `X-Frame-Options: SAMEORIGIN` is sent.

Known limits:

* GET requests are not checked, and two of them write: `GET /api/projects/<id>/next` takes or refreshes a
  task lock for the person (24 h), and `GET /logout` ends a password session (a header session comes back
  on the next request). A sibling page can trigger them, for example through an `<img>`.
* A browser that sends neither `Sec-Fetch-Site` nor `Origin` on an unsafe request is not a conforming one.
* Cookie tossing: a sibling host can set a `sessionid` or `csrftoken` cookie with `Domain=<parent>`.
  `SESSION_COOKIE_NAME=__Host-sessionid` (with Secure and Path=/) would close the first; not done.

## Running the tests

They need the image's dependencies, so run them inside the base image:

```bash
docker run --rm --platform linux/amd64 --user root --entrypoint sh \
  -v "$PWD/label_studio/core/settings/base.py:/label-studio/label_studio/core/settings/base.py:ro" \
  -v "$PWD/label_studio/users/remote_user.py:/label-studio/label_studio/users/remote_user.py:ro" \
  -v "$PWD/label_studio/users/tests/test_remote_user.py:/label-studio/label_studio/users/tests/test_remote_user.py:ro" \
  heartexlabs/label-studio:1.23.2 \
  -c 'pip install -q pytest==7.2.2 pytest-django==4.9.0 pytest-env==0.6.2 factory_boy \
      && cd /label-studio/label_studio && python -m pytest users/tests/test_remote_user.py -q'
```

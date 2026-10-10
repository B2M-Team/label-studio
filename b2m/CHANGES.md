# B2Metric changes to Label Studio

This fork tracks upstream release tags of [HumanSignal/label-studio](https://github.com/HumanSignal/label-studio)
(Apache License 2.0, see `LICENSE` and `NOTICE`). Per section 4(b) of the license, the files
changed from the upstream release are listed here; each carries its own notice.

Base: tag `1.23.2` (`df96d79`).

| File | Change |
| --- | --- |
| `label_studio/users/remote_user.py` | New. Sign in from the email header of a trusted authenticating reverse proxy, allowlist only. |
| `label_studio/core/settings/base.py` | When `LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER` is set, add the middleware and backend above. Unset (the default) changes nothing. |
| `label_studio/users/tests/test_remote_user.py` | New. Tests for the above. |
| `b2m/` | New. Image build and this file. |

## Remote-user sign-in

Community has no SSO. This adds the smallest thing that lets a deployment behind oauth2-proxy
(nginx `auth-url`, which already authenticates against Keycloak) skip a second login.

* Set `LABEL_STUDIO_REMOTE_USER_EMAIL_HEADER=X-Auth-Request-Email` (the header the proxy sets).
* The header must match an existing, active account (case-insensitive). Unknown emails get no
  session and **no account is created**: every Community account is an organization admin, so
  auto-creating everyone the proxy admits would expose all projects and annotations.
* A password or token session is never replaced by the header. A session opened from the header
  follows it: another email switches the user, no header ends the session.
* The deployment must ensure only the proxy can reach the app and that the proxy overwrites a
  client-supplied copy of the header. Without that, anyone can claim any email.

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

# Test-only target container for the §1.4a live-tool tier (docs/testing-plan.md).
# Runs ONLY on the per-session Docker network created by
# backend/tests/integration/tools/conftest.py's docker_network fixture -
# never published to the host, never reachable from a real network.
#
# The account/password below is a FIXED, OBVIOUSLY-FAKE, LOCAL-ONLY TEST
# CREDENTIAL seeded on purpose so hydra/telnet-probe tests have a known weak
# login to find. It is not a secret and must never be reused anywhere real.
FROM alpine:3.21

RUN apk add --no-cache busybox-extras shadow \
    && adduser -D momos-test \
    && echo "momos-test:momos-test-weak-pw" | chpasswd

EXPOSE 23

# busybox telnetd forks /bin/login per connection, which reads /etc/shadow
# itself - no extra PAM wiring needed on Alpine's busybox-based login.
CMD ["telnetd", "-F", "-p", "23", "-l", "/bin/login"]

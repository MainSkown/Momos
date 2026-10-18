# Test-only target container for the §1.4a live-tool tier (docs/testing-plan.md).
# Runs ONLY on the per-session Docker network created by
# backend/tests/integration/tools/conftest.py's docker_network fixture -
# never published to the host, never reachable from a real network.
#
# The account/password below is a FIXED, OBVIOUSLY-FAKE, LOCAL-ONLY TEST
# CREDENTIAL seeded on purpose so hydra/ssh_probe tests have a known weak
# login to find. It is not a secret and must never be reused anywhere real.
FROM alpine:3.21

RUN apk add --no-cache openssh-server shadow \
    && ssh-keygen -A \
    && adduser -D momos-test \
    && echo "momos-test:momos-test-weak-pw" | chpasswd \
    # Password auth must be explicitly enabled - Alpine's default sshd_config
    # ships with it commented out, which would make hydra's brute-force
    # (and the guided-session ssh tools) silently unable to log in at all.
    && sed -i \
        -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' \
        -e 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' \
        -e 's/^#\?UsePAM.*/UsePAM no/' \
        /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]

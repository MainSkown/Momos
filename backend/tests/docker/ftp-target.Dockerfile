# Test-only target container for the §1.4a live-tool tier (docs/testing-plan.md).
# Runs ONLY on the per-session Docker network created by
# backend/tests/integration/tools/conftest.py's docker_network fixture -
# never published to the host, never reachable from a real network.
#
# The account/password below is a FIXED, OBVIOUSLY-FAKE, LOCAL-ONLY TEST
# CREDENTIAL seeded on purpose so hydra/ftp-session tests have a known weak
# login to find. It is not a secret and must never be reused anywhere real.
FROM alpine:3.21

RUN apk add --no-cache vsftpd shadow \
    && adduser -D -h /home/momos-test momos-test \
    && echo "momos-test:momos-test-weak-pw" | chpasswd \
    # Small, fixed file tree the FTP-session tier can read deterministically.
    && mkdir -p /home/momos-test/public/docs \
    && echo "momos ftp smoke-test file" > /home/momos-test/public/readme.txt \
    && echo "nested fixed file for recursive listing tests" > /home/momos-test/public/docs/notes.txt \
    && chown -R momos-test:momos-test /home/momos-test

# Local, non-anonymous logins only, writes allowed within the seeded home
# directory, passive mode enabled with a narrow fixed port range so the
# container needs no extra published ports beyond 21 + this range.
RUN { \
      echo "listen=YES"; \
      echo "anonymous_enable=NO"; \
      echo "local_enable=YES"; \
      echo "write_enable=YES"; \
      echo "chroot_local_user=YES"; \
      echo "allow_writeable_chroot=YES"; \
      echo "pasv_enable=YES"; \
      echo "pasv_min_port=21100"; \
      echo "pasv_max_port=21110"; \
      echo "seccomp_sandbox=NO"; \
    } > /etc/vsftpd/vsftpd.conf

EXPOSE 21 21100-21110

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd/vsftpd.conf"]

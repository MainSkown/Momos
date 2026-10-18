# Test-only target container for the §1.4a live-tool tier (docs/testing-plan.md).
# Runs ONLY on the per-session Docker network created by
# backend/tests/integration/tools/conftest.py's docker_network fixture -
# never published to the host, never reachable from a real network.
#
# No credentials here (plain static content), but still local-only/
# disposable like the other three target images - never exposed to a real
# network. The seeded paths below are FIXED and deliberately include one
# path that does NOT exist, so gobuster's directory-brute tests have both a
# known-present and a known-absent case to assert against.
FROM nginx:alpine

COPY site/ /usr/share/nginx/html/

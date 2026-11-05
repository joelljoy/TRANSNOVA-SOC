# syntax=docker/dockerfile:1
#
# Cowrie SSH decoy for PS04: upstream Cowrie 3.1.4 (pinned by digest) plus our
# config, credential policy and synthetic decoy filesystem baked in, so the
# running container needs no host bind mounts.

ARG COWRIE_IMAGE=cowrie/cowrie@sha256:baf351038db967704dfa39f7ce860e8875c9456cdab72a9d3257c4247211050d

# Build stage: assemble /build/etc (config + userdb + fs.pickle with decoy-fs/).
# The upstream image is distroless, so file modes are set with its Python.
FROM ${COWRIE_IMAGE} AS fsbuild
USER root
COPY build_fs.py /build/build_fs.py
COPY decoy-fs /build/decoy-fs
COPY cowrie.cfg userdb.txt /build/etc/
RUN ["/cowrie/cowrie-env/bin/python3", "/build/build_fs.py", "/build/decoy-fs", "/build/etc/fs.pickle"]
RUN ["/cowrie/cowrie-env/bin/python3", "-c", "import os; [os.chmod(os.path.join('/build/etc', f), 0o444) for f in os.listdir('/build/etc')]; os.chmod('/build/etc', 0o555)"]
COPY harden_cowrie.py soc_redact.py /build/
RUN ["/cowrie/cowrie-env/bin/python3", "/build/harden_cowrie.py", "/cowrie/cowrie-git/src/cowrie", "/build/patched", "/build/soc_redact.py"]

FROM ${COWRIE_IMAGE}
# Root-owned and read-only for the cowrie user (uid 999).
COPY --from=fsbuild --chown=0:0 /build/etc /etc/cowrie
COPY --from=fsbuild --chown=0:0 /build/patched/ /cowrie/cowrie-git/src/cowrie/
USER 999:999
EXPOSE 2222

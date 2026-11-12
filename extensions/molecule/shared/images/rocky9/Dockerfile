FROM docker.io/rockylinux/rockylinux:9

ENV container=docker

RUN dnf -y install systemd python3 python3-dnf sudo rpm-build rpm-sign gnupg2 \
    && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dbus \
        iproute2 \
        less \
        lsof \
        net-tools \
        openssh-client \
        openssl \
        procps \
        python3 \
        rsync \
        sudo \
        systemd \
        systemd-sysv \
        wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash knims \
    && printf 'knims ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/knims \
    && chmod 0440 /etc/sudoers.d/knims

WORKDIR /home/knims/KN-IMS

COPY --chown=knims:knims . /home/knims/KN-IMS

EXPOSE 3306 8080 9000

VOLUME ["/sys/fs/cgroup"]

STOPSIGNAL SIGRTMIN+3

CMD ["/sbin/init"]

FROM alpine:3.23.3

RUN apk add --no-cache \
      openssh bash shadow \
      htop btop \
      curl jq \
      tzdata \
      vim \
      musl-locales \
      musl-locales-lang \
  && mkdir -p /var/run/sshd \
  && ssh-keygen -A \
  && sed -i \
      -e 's/#PasswordAuthentication yes/PasswordAuthentication yes/' \
      -e 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' \
      /etc/ssh/sshd_config \
  && printf "\nPubkeyAuthentication no\nUsePAM no\n" >> /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd","-D","-e"]

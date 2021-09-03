FROM alpine
ENV RECOVER_GH_SECRETS_CRTFILE=/certs/nip.io/nip.pem
ENV RECOVER_GH_SECRETS_KEYFILE=/certs/nip.io/nip-key.pem
COPY . /
ENTRYPOINT ["/recover-gh-secrets"]

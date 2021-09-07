FROM alpine
COPY . /
ENTRYPOINT ["/recover-gh-secrets"]

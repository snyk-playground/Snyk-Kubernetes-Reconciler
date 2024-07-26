FROM --platform=linux/amd64 cgr.dev/chainguard/python:latest-dev

WORKDIR /usr/app/sec

COPY . ./

USER root
RUN apk add docker

RUN addgroup docker
RUN addgroup nonroot docker
RUN pip install -r requirements.txt

LABEL org.opencontainers.image.source="https://github.com/snyk-playground/Snyk-Kubernetes-Reconciler"
LABEL io.snyk.containers.image.dockerfile="/Dockerfile"
LABEL io.snyk.containers.repo.branch="main"

COPY --from=snyk/snyk:linux /usr/local/bin/snyk /usr/local/bin/snyk
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["sh", "-c","mkdir $HOME/.docker && cp -r /tmp/.docker/..data/config.json $HOME/.docker && dockerd --iptables=false >/dev/null & python3 main.py"]
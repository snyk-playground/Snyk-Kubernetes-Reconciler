FROM --platform=linux/amd64 cgr.dev/chainguard/python:latest-dev

WORKDIR /usr/app/sec

COPY . ./

USER root
RUN apk add docker

RUN addgroup docker
RUN addgroup nonroot docker
RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir requests kubernetes

COPY --from=snyk/snyk:linux /usr/local/bin/snyk /usr/local/bin/snyk
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["sh", "-c","mkdir $HOME/.docker && cp -r /tmp/.docker/..data/config.json $HOME/.docker && dockerd --iptables=false >/dev/null & python3 main.py"]
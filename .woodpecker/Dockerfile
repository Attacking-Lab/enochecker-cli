# Woodpecker CI runner image for .woodpecker/test.yml. Bundles git, uv
# and just on top of a plain Python image, so a run pays for this setup
# once, at image build time, instead of on every push. Built and pushed
# automatically by .woodpecker/ci-image.yml whenever this file changes
# (see the justfile's ci-image-build/ci-image-push recipes for the
# equivalent by-hand commands, still useful for local testing).
# Modelled on atklab/enochecker-exploit's .woodpecker/Dockerfile.
FROM python:3.13-slim-bookworm

ARG JUST_VERSION=1.58.0

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV UV_LINK_MODE=copy

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.8.5 /uv /uvx /usr/local/bin/

RUN curl -fsSL \
        "https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
        -o /tmp/just.tar.gz \
    && tar -xzf /tmp/just.tar.gz -C /usr/local/bin just \
    && rm /tmp/just.tar.gz

WORKDIR /woodpecker/src

unexport VIRTUAL_ENV

UV_FLAGS := env('UV_FLAGS', '--inexact --no-group prod --group dev --all-extras')
UV_RUN := 'env VIRTUAL_ENV=.venv uv run ' + UV_FLAGS

# Image built from .woodpecker/Dockerfile for the Woodpecker CI pipeline
CI_IMAGE := env('CI_IMAGE', 'oci.atklab.cloud/enochecker-cli/enochecker-cli-ci')
CI_IMAGE_TAG := env('CI_IMAGE_TAG', 'latest')
CI_IMAGE_REF := CI_IMAGE + ':' + CI_IMAGE_TAG

[private]
default:
    @just --list

# Format, lint, type-check and test
[group('test')]
all: format lint mypy test

# Auto-fix formatting and lint issues
[group('dev')]
fix: format-fix lint-fix

# Check formatting
[group('dev')]
format:
    @{{ UV_RUN }} --group format ruff format --check

# Apply formatting
[group('dev')]
format-fix:
    @{{ UV_RUN }} --group format ruff format

# Lint sources
[group('dev')]
lint:
    @{{ UV_RUN }} --group lint ruff check

# Auto-fix lint issues
[group('dev')]
lint-fix:
    @{{ UV_RUN }} --group lint ruff check --fix

# Type-check sources
[group('dev')]
mypy:
    @{{ UV_RUN }} --group typing mypy src/enochecker_cli/

# Build sdist/wheel
[group('build')]
build:
    @uv build

# Run the test suite, if any tests exist
[group('test')]
test:
    #!/usr/bin/env sh
    set -e
    if [ -d tests ]; then
        {{ UV_RUN }} --group test coverage run -m pytest -W error -v
        {{ UV_RUN }} --group test coverage report -m
    fi

# Sync the dev environment
[group('dev')]
sync:
    @uv sync {{ UV_FLAGS }}

# Wire up the local enochecker-core submodule for development
[group('dev')]
dev:
    @git update-index --assume-unchanged lib/.enochecker-core/pyproject.toml
    @rm -rf lib/.enochecker-core
    @ln -s enochecker-core lib/.enochecker-core
    @git submodule update --init --recursive lib/enochecker-core

# Build the Woodpecker CI runner image
[group('build')]
ci-image-build:
    docker build -f .woodpecker/Dockerfile -t {{ CI_IMAGE_REF }} .

# Build and push the Woodpecker CI runner image
[group('build')]
ci-image-push: ci-image-build
    docker push {{ CI_IMAGE_REF }}

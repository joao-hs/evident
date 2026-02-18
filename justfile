# Set shell (optional, but helps cross-platform compatibility)

set shell := ["bash", "-cu"]

# === CONFIG ===

CLIENT_DIR := "client"
SERVER_DIR := "server"
SERVER_TARGET_DIR := "server/target"
IMAGE_DIR := "image"
CLIENT_BIN := "evident"
TESTENV_DIR := "client/test-env"
GO_INSTALL_DIR := "~/go/bin"
PROVIDER_MAIN_PATH := "cmd/provider/main.go"

# Default recipe:
default:
    just --list

build-client:
    cd {{ CLIENT_DIR }} && go build -o {{ CLIENT_BIN }} main.go

prepare-client-env: build-client
    rm -rf {{ TESTENV_DIR }}
    mkdir -p {{ TESTENV_DIR }}
    cp -r {{ IMAGE_DIR }}/* {{ TESTENV_DIR }}
    rsync -avq --exclude '{{ SERVER_TARGET_DIR }}' {{ SERVER_DIR }} {{ TESTENV_DIR }}
    cd {{ TESTENV_DIR }} && \
        git init && \
        git add .
    cp {{ CLIENT_DIR }}/{{ CLIENT_BIN }} {{ TESTENV_DIR }}

install-provider:
    cd {{ CLIENT_DIR }} && go build -o {{ GO_INSTALL_DIR }}/terraform-provider-evident {{ PROVIDER_MAIN_PATH }}

install-client: build-client
    cp -f {{ CLIENT_DIR }}/{{ CLIENT_BIN }} {{ GO_INSTALL_DIR }}/

# === GLOBAL ===

clean:
    rm {{ CLIENT_DIR }}/{{ CLIENT_BIN }}
    cd {{ SERVER_DIR }} && \
        cargo clean
    rm -rf {{ TESTENV_DIR }}

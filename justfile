# Set shell (optional, but helps cross-platform compatibility)

set shell := ["bash", "-cu"]

# === CONFIG ===

CLIENT_DIR := "client"
SERVER_DIR := "server"
SERVER_TARGET_DIR := "server/target"
INSTANCE_DIR := "instance"
INSTANCE_TARGET_DIR := "instance/target"
IMAGE_DIR := "image"
CLIENT_BIN := "evident"
TESTENV_DIR := "client/test-env"
GO_INSTALL_DIR := "~/go/bin"
PROVIDER_MAIN_PATH := "cmd/provider/main.go"

# Default recipe:
default:
    just --list

gen-proto-client:
    cd {{ CLIENT_DIR }} && buf generate

build-client-keep-proto:
    cd {{ CLIENT_DIR }} && go build -o {{ CLIENT_BIN }} main.go

build-client: gen-proto-client
    cd {{ CLIENT_DIR }} && go build -o {{ CLIENT_BIN }} main.go

prepare-client-env: build-client
    rm -rf {{ TESTENV_DIR }}
    mkdir -p {{ TESTENV_DIR }}
    cp -r {{ IMAGE_DIR }}/* {{ TESTENV_DIR }}
    rsync -avq --exclude '{{ INSTANCE_TARGET_DIR }}' {{ INSTANCE_DIR }} {{ TESTENV_DIR }}
    cd {{ TESTENV_DIR }} && \
        git init && \
        git add .
    cp {{ CLIENT_DIR }}/{{ CLIENT_BIN }} {{ TESTENV_DIR }}

install-provider: gen-proto-client
    cd {{ CLIENT_DIR }} && go build -o {{ GO_INSTALL_DIR }}/terraform-provider-evident {{ PROVIDER_MAIN_PATH }}

install-client: build-client
    cp -f {{ CLIENT_DIR }}/{{ CLIENT_BIN }} {{ GO_INSTALL_DIR }}/

build-server-debug feature:
    cd {{ SERVER_DIR }} && cargo build --features="{{ feature }}"

# === GLOBAL ===

clean:
    rm {{ CLIENT_DIR }}/{{ CLIENT_BIN }}
    cd {{ SERVER_DIR }} && \
        cargo clean
    rm -rf {{ TESTENV_DIR }}

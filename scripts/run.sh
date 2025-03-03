#!/bin/bash
set -e

GIT_ROOT=$(git rev-parse --show-toplevel)
PWD=$(pwd)
cd ${GIT_ROOT}

cleanup() {
  pwd
}

trap cleanup EXIT

 docker compose up --build -d
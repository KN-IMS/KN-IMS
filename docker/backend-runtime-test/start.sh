#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PLATFORM="${PLATFORM:-linux/amd64}"
IMAGE_NAME="${IMAGE_NAME:-knims-backend-runtime-test:22.04}"
CONTAINER_NAME="${CONTAINER_NAME:-knims-backend-runtime-test}"

docker build \
    --platform "${PLATFORM}" \
    -f "${ROOT_DIR}/docker/backend-runtime-test/Dockerfile" \
    -t "${IMAGE_NAME}" \
    "${ROOT_DIR}"

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d \
    --platform "${PLATFORM}" \
    --privileged \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --name "${CONTAINER_NAME}" \
    "${IMAGE_NAME}" >/dev/null

cat <<EOF
container started: ${CONTAINER_NAME}
platform: ${PLATFORM}

shell:
  docker exec -it -u knims ${CONTAINER_NAME} bash

inside container:
  cd /home/knims/KN-IMS
  sudo ./setup_backend_agent_runtime.sh -m backend
EOF

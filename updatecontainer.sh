#!/bin/bash
set -euo pipefail

AWS_REGION="eu-west-3"
REPOSITORY="hennge-one"
CONTAINER_NAME="hennge-one"
HOST_PORT=443
CONTAINER_PORT=443
NETWORK="hennge-net"

if ! command -v aws >/dev/null 2>&1; then
  echo "AWS CLI not found, installing it..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq awscli
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE="${REGISTRY}/${REPOSITORY}:latest"

echo "Logging in to ECR (${REGISTRY})..."
aws ecr get-login-password --region "$AWS_REGION" | sudo docker login --username AWS --password-stdin "$REGISTRY"

echo "Pulling ${IMAGE}..."
sudo docker pull "$IMAGE"

echo "Stopping previous container (if any)..."
sudo docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
sudo docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "Ensuring shared network '${NETWORK}' exists..."
sudo docker network create "$NETWORK" >/dev/null 2>&1 || true

if sudo docker inspect postgres >/dev/null 2>&1; then
  echo "Attaching postgres container to '${NETWORK}' (if not already)..."
  sudo docker network connect "$NETWORK" postgres >/dev/null 2>&1 || true
fi

echo "Starting new container..."
sudo docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  --network "$NETWORK" \
  --dns-search . \
  -p "${HOST_PORT}:${CONTAINER_PORT}" \
  -p 80:80 \
  "$IMAGE"

echo "Waiting for the container to come up..."
sleep 3

if [ "$(sudo docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" != "true" ]; then
  echo "ERROR: ${CONTAINER_NAME} did not start. Recent logs:"
  sudo docker logs --tail 50 "$CONTAINER_NAME" || true
  exit 1
fi

echo "Deployed ${IMAGE} successfully."

echo "Cleaning up dangling images..."
sudo docker image prune -f >/dev/null 2>&1 || true

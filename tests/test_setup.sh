#!/bin/bash

set -euxo pipefail

echo "Copying docker-compose override file"
cp ./tests/files/docker-compose.override.yml ./netbox-docker/

echo "Copying Dockerfile"
cp ./tests/files/Dockerfile ./netbox-docker/

echo "Copying whl"
WHL_FILE=$(ls ./dist/ | grep .whl)
cp  "./dist/$WHL_FILE" ./netbox-docker/

echo "Modify configuration.py"
sed -i 's/^PLUGINS = .*/PLUGINS = \["netbox_lists"\]/' ./netbox-docker/configuration/configuration.py

echo "::group::docker"

echo "Copying Dockerfile"
cp ./tests/files/Dockerfile ./

echo "Running docker-compose up"
cd netbox-docker
docker-compose build --build-arg "FROM=netboxcommunity/netbox:$NETBOX_CONTAINER_TAG" --build-arg "WHL_FILE=$WHL_FILE"
docker-compose up -d

echo "::endgroup::"

echo "::group::Wait for NetBox to start"
# NetBox v2.11 might take more time to start
# due to all the migrations that have to be applied
for i in {1..20}; do curl -Ss http://localhost:8000/api/status/ && break || echo -e "\033[0;33mNot started yet ($i)\033[0m" && sleep 10; done

set +e
curl -Ss http://localhost:8000/api/status/
CURL_RET=$?
set -e


if [ "$CURL_RET" -ne 0 ]; then
    echo "::error NetBox failed to start."
    docker-compose logs
    exit $CURL_RET
fi

echo -e "\033[0;32mNetBox started\033[0m"
echo "::endgroup::"

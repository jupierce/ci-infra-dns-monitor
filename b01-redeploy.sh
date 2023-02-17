#!/bin/bash

docker build . -t dns-monitor
docker tag dns-monitor quay.io/jupierce/infra-dns-monitor:build01
docker push quay.io/jupierce/infra-dns-monitor:build01
oc --as system:admin delete --context build01 -n ci-infra-dns-monitor ds/ci-infra-dns-monitor
oc --as system:admin apply --context build01 -f b01-resources.yaml
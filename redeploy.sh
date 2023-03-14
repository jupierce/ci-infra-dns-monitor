#!/bin/bash

if [[ -z "$1" ]]; then
  echo "Specify at least one context (e.g. build01) as a command line argument."
  exit 1
fi

docker build . -t dns-monitor
docker tag dns-monitor quay.io/jupierce/infra-dns-monitor:ephemeral-node
docker push quay.io/jupierce/infra-dns-monitor:ephemeral-node

for context in $@ ; do
  echo "Applying to context: ${context}"
  oc --as system:admin delete --context ${context} -n ephemeral-node-dns-monitor ds --all
  oc --as system:admin apply --context ${context} -f resources.yaml
done

#!/bin/bash

if [[ -z "$1" ]]; then
  echo "Specify at least one context (e.g. build01) as a command line argument."
  exit 1
fi

docker build . -t dns-monitor
docker tag dns-monitor quay.io/jupierce/infra-dns-monitor:prod
docker push quay.io/jupierce/infra-dns-monitor:prod

for context in $@ ; do
  echo "Applying to context: ${context}"
  oc --as system:admin delete --context ${context} -n ci-infra-dns-monitor ds --all
  oc --as system:admin apply --context ${context} -f resources.yaml

  if ! oc --as system:admin get secrets --context ${context} -n ci-infra-dns-monitor openshift-gce-devel-kettle; then
    oc --as system:admin --context ${context} -n ci-infra-dns-monitor create secret generic openshift-gce-devel-kettle --from-file openshift-gce-devel-kettle.json
  fi

done

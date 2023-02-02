#!/usr/bin/env bash
BRANCH="v1.2"
while getopts o:f:d:b: flag
do
    case "${flag}" in
        o) OSM=${OPTARG};;
        f) RESET_SC=${OPTARG};;
        d) KAFKA_DEBUG=${OPTARG};;
        b) BRANCH=${OPTARG};;
        *) echo "Invalid flags, stopping script"; exit 1 ;;
    esac
done
if [ "$RESET_SC" == "1" ]; then
  echo "Existing security controls rules will be flushed at rr-tool startup"
  sed -n '/RESET_SECURITY_CONTROLS_RULES_AT_STARTUP/{n;s/.*/          value: "1"/}' pod.yaml
elif [ "$RESET_SC" == "0" ]; then
  echo "Existing security controls rules will be kept"
  sed -n '/RESET_SECURITY_CONTROLS_RULES_AT_STARTUP/{n;s/.*/          value: "0"/}' pod.yaml
else
  echo "Unknown RESET_SECURITY_CONTROLS_RULES_AT_STARTUP option, pod.yaml related setting will be followed"
fi
if [ "$KAFKA_DEBUG" == "1" ]; then
  echo "Using debug Kafka topics"
  sed -n '/KAFKA_DEBUG/{n;s/.*/          value: "1"/}' pod.yaml
elif [ "$KAFKA_DEBUG" == "0" ]; then
  echo "Using production Kafka topics"
  sed -n '/KAFKA_DEBUG/{n;s/.*/          value: "0"/}' pod.yaml
else
  echo "Unknown KAFKA_DEBUG option, pod.yaml related setting will be followed"
fi
echo "Refreshing code"
cd /media/palantir-nfs/ti-re && git fetch && git checkout "$BRANCH" && git pull origin "$BRANCH"
echo "Rebuilding RR-tool docker image..."
cd /media/palantir-nfs/ti-re/rr-tool && docker build -t palantir-rr-tool:1.0 . && docker tag palantir-rr-tool:1.0 10.101.10.244:5000/palantir-rr-tool:1.0 && docker push 10.101.10.244:5000/palantir-rr-tool:1.0
if [ "$OSM" == "0" ]; then
  echo "Disabling OSM connection"
  sed -n '/ENABLE_MANO_API/{n;s/.*/          value: "0"/}' pod.yaml
elif [ "$OSM" == "1" ]; then
  echo "Enabling OSM connection"
  sed -n '/ENABLE_MANO_API/{n;s/.*/          value: "1"/}' pod.yaml
else
  echo "Unknown OSM connection option, ignoring..."
fi
if [[ $(kubectl get pods --all-namespaces | grep -c rr-tool) -gt 0 ]]; then
  echo "Existing RR-tool pod found, deleting..."
  kubectl delete pod rr-tool
fi
echo "Creating RR-tool pod"
kubectl create -f /media/palantir-nfs/ti-re/rr-tool/pod.yaml
echo "Waiting for RR-tool pod startup"
while [[ $(kubectl get pods --all-namespaces | grep rr-tool | grep -c Running) -eq 0 ]]; do
  echo -n "."
done
echo

#if [ $# -eq 1 ]; then
#  if [ "$1" = "netflow_test" ]; then
#    echo "Injecting netflow alerts..."
#    cd /media/palantir-nfs/ti-re/rr-tool && python3 -c "import rr_tool_helper; rr_tool_helper.inject_netflow_alerts()"
#    echo "Netflow alerts injected"
#  fi
#fi

echo "RR-tool pod started, attaching..."
kubectl logs rr-tool && kubectl attach rr-tool

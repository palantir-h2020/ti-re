#!/usr/bin/env bash
echo "Resetting iptables..."
cd /media/palantir-nfs/ti-re/rr-tool && python3 -c "from scripts import rr_tool_helper; rr_tool_helper.flush_filtering_rules()"
echo "Rebuilding RR-tool docker image..."
cd /media/palantir-nfs/ti-re && git pull && cd rr-tool && docker build -t palantir-rr-tool:1.0 . && docker tag palantir-rr-tool:1.0 10.101.10.244:5000/palantir-rr-tool:1.0 && docker push 10.101.10.244:5000/palantir-rr-tool:1.0
if [[ $(kubectl get pods --all-namespaces | grep rr-tool | wc -l) -gt 0 ]]; then
  echo "Existing RR-tool pod found, deleting..."
  kubectl delete pod rr-tool
fi
echo "Creating RR-tool pod"
kubectl create -f /media/palantir-nfs/ti-re/rr-tool/pod.yaml
echo "Waiting for RR-tool pod startup"
while [[ $(kubectl get pods --all-namespaces | grep rr-tool | grep Running | wc -l) -eq 0 ]]; do
  echo -n "."
done
echo

if [ $# -eq 1 ]; then
  if [ "$1" = "netflow_test" ]; then
    echo "Injecting netflow alerts..."
    cd /media/palantir-nfs/ti-re/rr-tool && python3 -c "import rr_tool_helper; rr_tool_helper.inject_netflow_alerts()"
    echo "Netflow alerts injected"
  fi
fi

echo "RR-tool pod started, attaching..."
kubectl logs rr-tool && kubectl attach rr-tool
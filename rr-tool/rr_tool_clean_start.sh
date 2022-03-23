#!/usr/bin/env bash
echo "Resetting iptables..."
cd /media/palantir-nfs/ti-re/rr-tool && python3 -c "import reset_iptables; reset_iptables.flush_filtering_rules()"
echo "Rebuilding rr-tool docker image..."
cd /media/palantir-nfs/ti-re && git pull && cd rr-tool && docker build -t palantir-rr-tool:1.0 . && docker tag palantir-rr-tool:1.0 10.101.10.244:5000/palantir-rr-tool:1.0 && docker push 10.101.10.244:5000/palantir-rr-tool:1.0
if [[ $(kubectl get pods --all-namespaces | grep rr-tool | wc -l) -gt 0 ]]; then
  echo "Existing rr-tool pod found, deleting..."
  kubectl delete pod rr-tool
fi
echo "Creating rr-tool pod"
kubectl create -f /media/palantir-nfs/ti-re/rr-tool/pod.yaml
if [[ $(kubectl get pods --all-namespaces | grep rr-tool | grep Running | wc -l) -eq 0 ]]; then
  echo -n "."
fi
echo "Rr-tool pod created, attaching..."
kubectl logs rr-tool && kubectl attach rr-tool
#!/usr/bin/env bash
cd /media/palantir-nfs/ti-re/rr-tool && python3 -c "import reset_iptables; reset_iptables.flush_filtering_rules()"
cd /media/palantir-nfs/ti-re && git pull && cd rr-tool && docker build -t palantir-rr-tool:1.0 . && docker tag palantir-rr-tool:1.0 10.101.10.244:5000/palantir-rr-tool:1.0 && docker push 10.101.10.244:5000/palantir-rr-tool:1.0
if [[ $(kubectl get pods --all-namespaces | grep rr-tool | wc -l) -gt 0 ]]; then
  kubectl delete pod rr-tool
fi
kubectl create -f /media/palantir-nfs/ti-re/pod.yaml && sleep 5 && kubectl attach rr-tool
# ti-re

Threat Intelligence / Remediation Engine

To deploy the Remediation engine, it is sufficient to clone this repo and execute on the target master Kubernetes node the rr_tool_clean_start.sh Bash script in the rr-tool folder. The script will provide a fresh install of the tool, by rebuilding the Docker image and deploy it in a Kubernetes pod.

By default the tool will automatically deploy remediations by reconfiguring security controls through the OSM orchestrator. To disable this feature, execute the rr_tool_clean_start.sh script suffixed with the `-o 0` option.

All the configuration options may be edited in the pod.yaml file in the rr-tool folder, before running the rr_tool_clean_start.sh script.

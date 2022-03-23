#!/usr/bin/env bash
bash rr_tool_clean_start.sh
echo "Injecting netflow alerts..."
cd /media/palantir-nfs/ti-re/rr-tool && python3 -c "import rr_tool_helper; rr_tool_helper.inject_netflow_alerts()"
echo "Netflow alerts injected"
#!/usr/bin/env python3
import sys
import subprocess
import yaml

branch = "multi_tenancy"
tenant = 1000

def execute_command(command):
    subprocess.run(command, shell=True, check=True)

def main():

    with open('pod.yaml', 'r') as file:
        yaml_data = yaml.safe_load(file)
    env_vars = yaml_data['spec']['containers'][0]['env']

    osm = None
    reset_sc = None
    kafka_debug = None

    args = sys.argv[1:]
    while args:
        flag = args.pop(0)
        if flag == "-o":
            osm = args.pop(0)
        elif flag == "-f":
            reset_sc = args.pop(0)
        elif flag == "-d":
            kafka_debug = args.pop(0)
        elif flag == "-b":
            branch = args.pop(0)
        elif flag == "-t":
            tenant = args.pop(0)
        else:
            print("Invalid flags, stopping script")
            sys.exit(1)

    print("Refreshing code")
    execute_command("cd /media/palantir-nfs/ti-re && git fetch && git checkout {} && git pull origin {}".format(branch, branch))

    if reset_sc == "1":
        print("Existing security controls rules will be flushed at rr-tool startup")
    elif reset_sc == "0":
        print("Existing security controls rules will be kept")
    else:
        print("Unknown RESET_SECURITY_CONTROLS_RULES_AT_STARTUP option, pod.yaml related setting will be followed")

    if kafka_debug == "1":
        print("Using debug Kafka topics")
    elif kafka_debug == "0":
        print("Using production Kafka topics")
    else:
        print("Unknown KAFKA_DEBUG option, pod.yaml related setting will be followed")

    #execute_command(f'sed -n "/TO_BE_SUBSTITUTED_BY_LAUNCH_SCRIPT/{tenant}/" pod.yaml')
    execute_command("sed -n '/RR_INSTANCE_IDENTIFIER/{n;s/.*/          value: \"{}\"/}' pod.yaml".format(tenant))
    
    print("Rebuilding RR-tool docker image...")
    execute_command("cd /media/palantir-nfs/ti-re/rr-tool && docker build -t palantir-rr-tool:1.0 . && docker tag palantir-rr-tool:1.0 10.101.10.244:5000/palantir-rr-tool:1.0 && docker push 10.101.10.244:5000/palantir-rr-tool:1.0")

    if osm == "0":
        print("Disabling OSM connection")
    elif osm == "1":
        print("Enabling OSM connection")
    else:
        print("Unknown OSM connection option, ignoring...")

    for env_var in env_vars:
        if env_var['name'] == 'RESET_SECURITY_CONTROLS_RULES_AT_STARTUP':
            env_var['value'] = str(reset_sc)
        if env_var['name'] == 'KAFKA_DEBUG_TOPICS':
            env_var['value'] = str(kafka_debug)
        if env_var['name'] == 'ENABLE_MANO_API':
            env_var['value'] = str(osm)
        if env_var['name'] == 'RR_INSTANCE_IDENTIFIER':
            env_var['value'] = str(tenant)

    with open('pod.yaml', 'w') as file:
        yaml.dump(yaml_data, file)

    return

    if subprocess.run(["kubectl", "get", "pods", "-n", tenant, "|", "grep", "-c", "rr-tool"], capture_output=True, text=True).stdout.strip() > "0":
        print("Existing RR-tool pod found, deleting...")
        execute_command(f"kubectl delete pod rr-tool -n {tenant}")

    print("Creating RR-tool pod")
    execute_command(f"kubectl create -f /media/palantir-nfs/ti-re/rr-tool/pod.yaml -n {tenant}")

    print("Waiting for RR-tool pod startup")
    while subprocess.run(["kubectl", "get", "pods", "-n", tenant, "|", "grep", "rr-tool", "|", "grep", "-c", "Running"], capture_output=True, text=True).stdout.strip() == "0":
        print(".", end="")
    
    print()

    # if len(sys.argv) == 2 and sys.argv[1] == "netflow_test":
    #     print("Injecting netflow alerts...")
    #     execute_command("cd /media/palantir-nfs/ti-re/rr-tool && python3 -c \"import rr_tool_helper; rr_tool_helper.inject_netflow_alerts()\"")
    #     print("Netflow alerts injected")

    print("RR-tool pod started, attaching...")
    execute_command(f"kubectl logs rr-tool -n {tenant}")
    execute_command(f"kubectl attach rr-tool -n {tenant}")

if __name__ == "__main__":
    main()

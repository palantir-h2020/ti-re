import logging
import requests
import portalAPI
from settings import *


def addNode(nodeName, nodeType):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new node {nodeName} deployed")


def addFirewall(newNodeName, path, capabilities):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new firewall node {newNodeName} deployed")


def add_filtering_rules(node1, iptables_rule):
    logging.info("Calling MANO API")
    logging.info("MANO API: adding filtering rule to iptables instance")
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    url = 'http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns/action?id=' + IPTABLES_SC_ID
    payload = {"action_name": "run", "action_params": {"cmd": iptables_rule["rule"].replace("iptables -A FORWARD","iptables -I FORWARD 1")+" -m comment --comment \"RR-TOOL_GENERATED\""}}

    if ENABLE_MANO_API == "1":
        r = requests.post(url, headers=headers, json=payload)

        logging.info("MANO API: response code from orchestrator " + str(r.status_code))
        if r.ok:
            logging.info("MANO API: new rule added")
            portalAPI.notify_portal(componentType="Recommendation and Remediation",
                                    componentId="0",
                                    actionName="Added filtering rule to iptables SC",
                                    actionDescription="iptables SC reconfigured with command: " + iptables_rule["rule"],
                                    onips=[node1["ipAddress"]])
        else:
            logging.info("MANO API: failed adding filtering rule to iptables instance")
            logging.info("MANO API: response headers from orchestrator " + str(r.headers))
            logging.info("MANO API: response text from orchestrator " + str(r.text))
    else:
        logging.info("MANO API: disabled, logging request data")
        logging.info("MANO API: request headers: "+str(headers))
        logging.info("MANO API: request url: "+str(url))
        logging.info("MANO API: request payload: " + str(payload))

def add_dns_policy(domain, rule):
    logging.info("Calling MANO API")
    logging.info("MANO API: new dns rules added")


def shutdown(node1):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: {node1} has been shutdown")


def isolate(node1):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: {node1} has been isolated")


def add_honeypot(vulnerability):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new honeypot with {vulnerability} deployed")


def add_network_monitor(newNodeName, path):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new network monitor node {newNodeName} deployed")


def move(node1, net):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: moved {node1} to {net}")

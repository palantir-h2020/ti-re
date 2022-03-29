import requests

from . import portal
from settings import *

from helpers.logging_helper import get_logger

logger = get_logger('MANO_API')


def addNode(node_name, node_type):
    logger.info(f"new node {node_name} deployed")


def addFirewall(new_node_name, path, capabilities):
    logger.info(f"new firewall node {new_node_name} deployed")


def add_filtering_rules(node1, iptables_rule):
    logger.info("adding filtering rule to iptables instance")
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    url = 'http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns/action?id=' + IPTABLES_SC_ID
    payload = {"action_name": "run", "action_params": {"cmd": iptables_rule["rule"]}}

    if ENABLE_MANO_API == "1":
        r = requests.post(url, headers=headers, json=payload)

        logger.info("response code from orchestrator " + str(r.status_code))
        if r.ok:
            logger.info("new rule added")
            portal.notify(componentType="Recommendation and Remediation",
                          component_id="0",
                          action_name="Added filtering rule to iptables SC",
                          action_description="iptables SC reconfigured with command: " + iptables_rule["rule"],
                          on_ips=[node1["ipAddress"]])
        else:
            logger.info("failed adding filtering rule to iptables instance")
            logger.info("response headers from orchestrator " + str(r.headers))
            logger.info("response text from orchestrator " + str(r.text))
    else:
        logger.info("disabled, logger request data")
        logger.info("request headers: " + str(headers))
        logger.info("request url: " + str(url))
        logger.info("request payload: " + str(payload))


def flush_filtering_rules(node1):
    logger.info("flushing filtering rule to iptables instance")
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    url = 'http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns/action?id=' + IPTABLES_SC_ID
    payload = {"action_name": "run", "action_params": {"cmd": "iptables-save | grep -v RR-TOOL_GENERATED | "
                                                              "iptables-restore"}}

    if ENABLE_MANO_API == "1":
        r = requests.post(url, headers=headers, json=payload)

        logger.info("response code from orchestrator " + str(r.status_code))
        if r.ok:
            logger.info("rules flushed")
            portal.notify(componentType="Recommendation and Remediation",
                          component_id="0",
                          action_name="Flushed rules on iptables SC",
                          action_description="iptables SC reconfigured with command: iptables-save | grep -v "
                                             "RR-TOOL_GENERATED | iptables-restore",
                          on_ips=[node1["ipAddress"]])
        else:
            logger.info("failed flushing rules on iptables instance")
            logger.info("response headers from orchestrator " + str(r.headers))
            logger.info("response text from orchestrator " + str(r.text))
    else:
        logger.info("disabled, logger request data")
        logger.info("request headers: " + str(headers))
        logger.info("request url: " + str(url))
        logger.info("request payload: " + str(payload))


def add_dns_policy(domain, rule):
    logger.info("new dns rules added")


def shutdown(node1):
    logger.info(f"{node1} has been shutdown")


def isolate(node1):
    logger.info(f"{node1} has been isolated")


def add_honeypot(vulnerability):
    logger.info(f"new honeypot with {vulnerability} deployed")


def add_network_monitor(new_node_name, path):
    logger.info(f"new network monitor node {new_node_name} deployed")


def move(node1, net):
    logger.info(f"moved {node1} to {net}")

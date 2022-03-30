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
    send_action(node=node1,
                payload={"action_name": "run", "action_params": {"cmd": iptables_rule["rule"]}},
                action_name="Add filtering rule to iptables SC",
                action_description="iptables SC reconfigured with command: " + iptables_rule["rule"],
                )


def flush_filtering_rules(node1):
    logger.info("flushing filtering rules on iptables instance")
    send_action(node=node1,
                payload={"action_name": "run", "action_params": {"cmd": "iptables-save | grep -v RR-TOOL_GENERATED | "
                                                                        "iptables-restore"}},
                action_name="Flush rules on iptables SC",
                action_description="iptables SC reconfigured with command: iptables-save | grep -v "
                                   "RR-TOOL_GENERATED | iptables-restore",
                )


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


def send_action(node,
                payload,
                action_name,
                action_description,
                headers={'accept': 'application/json', 'Content-Type': 'application/json'},
                url='http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns/action?id=',
                component_type="Recommendation and Remediation",
                component_id="0"):
    if ENABLE_MANO_API == "1":
        r = requests.post(url + node["id"], headers=headers, json=payload)

        logger.info("response code from orchestrator " + str(r.status_code))
        if r.ok:
            portal.notify(component_type=component_type,
                          component_id=component_id,
                          action_name=action_name,
                          action_description=action_description,
                          on_ips=[node["ipAddress"]])
            logger.info("action succeeded: " + action_name)
            logger.debug("response headers from orchestrator " + str(r.headers))
            logger.debug("response text from orchestrator " + str(r.text))
        else:
            logger.error("action failed: " + action_name)
            logger.error("response headers from orchestrator " + str(r.headers))
            logger.error("response text from orchestrator " + str(r.text))
    else:
        logger.info("disabled, logging request data")
        logger.info("request headers: " + str(headers))
        logger.info("request url: " + str(url))
        logger.info("request payload: " + str(payload))

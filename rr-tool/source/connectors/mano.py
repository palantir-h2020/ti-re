import json
import requests, time

from . import portal
from . import service_matching
from settings import *

from helpers.logging_helper import get_logger

logger = get_logger('MANO_API')


# noinspection PyUnusedLocal
def addNode(node, node_type):
    node_name = node["name"]
    logger.info(f"new node {node_name} deployed")


# noinspection PyUnusedLocal
def addFirewall(new_node, path, capabilities):

    # new_node["nodeType"] = "firewall"
    # new_node["rules_level_4"] = []
    # new_node["rules_level_7"] = []
    # new_node["capabilities"] = capabilities

    # service_matching.deploy_secap("level_4_filtring", ["iptnetflow"])

    check_secap_readiness("91a41534-7597-4975-8763-0642ef98c864")

    new_node_name = new_node["name"]
    new_node["id"] = "0"  # TODO get from orchestrator the id of the newly created firewall
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


# noinspection PyUnusedLocal
def add_dns_policy(domain, rule):
    logger.info("new dns rules added")


def shutdown(node1):
    logger.info(f"{node1} has been shutdown")

def add_link(node1, node2):
    logger.info(f"Added link between {node1} and {node2}")

def isolate(node1):
    logger.info(f"{node1} has been isolated")


def add_honeypot(vulnerability):
    logger.info(f"new honeypot with {vulnerability} deployed")


# noinspection PyUnusedLocal
def add_network_monitor(new_node, path):
    new_node_name = new_node["name"]
    logger.info(f"new network monitor node {new_node_name} deployed")


def move(node1, net):
    logger.info(f"moved {node1} to {net}")


def check_secap_liveness():
    pass

def send_action(node,
                payload,
                action_name,
                action_description,
                headers=None,
                base_url='http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns/action?id=',
                component_type="Recommendation and Remediation",
                component_id="0"):
    if headers is None:
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    url = base_url + node["id"]
    if ENABLE_MANO_API == "1":
        r = requests.post(url, headers=headers, json=payload)

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

def check_secap_readiness(secap_id):
    """Returns True if the securtiy capability is operational.
    Returns False otherwise."""

    url='http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns'

    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}

    if ENABLE_MANO_API == "1":

        counter = 0
        while counter < 20:
            counter += 1
            time.sleep(2)

            raw_response = requests.get(url, headers=headers)
            response = json.loads(raw_response.text)

            logger.info("response code from orchestrator " + str(raw_response.status_code))
            logger.info("response from orchestrator: ")
            logger.info(response)

            if not raw_response.ok:
                logger.error("response headers from orchestrator " + str(raw_response.headers))
                logger.error("response text from orchestrator " + str(raw_response.text))
                continue

            for secap in response.get("ns"):
                status = secap.get("status").get("operational")
                if secap.get("id") == secap_id and status == "running":
                    logger.error(f"The security capability with id:{secap_id} is operational")
                    return True


        logger.error("The security capability is not yet operational")
        return False

    else:
        logger.info("disabled, logging request data")
        logger.info("request headers: " + str(headers))
        logger.info("request url: " + str(url))
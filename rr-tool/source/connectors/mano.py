import json
import requests, time

from . import portal
from . import service_matching
from settings import *

from helpers.logging_helper import get_logger

logger = get_logger('MANO_API')

def check_secap_readiness(secap_id):
    """Returns True if the securtiy capability is operational.
    Returns False otherwise."""

    url='http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/api/v2/lcm/ns' + '?tenant_id=' + TENANT_ORCHESTRATOR

    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}

    if ENABLE_MANO_API == "1":

        counter = 0
        while counter < (20 * 5):
            counter += 1
            time.sleep(3)

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
                    logger.info(f"The security capability with id:{secap_id} is operational")
                    return True


        logger.error("The security capability is not yet operational")
        return False

    else:
        logger.info("disabled, logging request data")
        logger.info("request headers: " + str(headers))
        logger.info("request url: " + str(url))

# noinspection PyUnusedLocal
def addNode(node, node_type):
    node_name = node["name"]
    logger.info(f"new node {node_name} deployed")


# noinspection PyUnusedLocal
def addFirewall(new_node, path, capabilities):

    secap_id = service_matching.deploy_secap("level_4_filtering", ["snort_ns"]) #iptnetflow_cnf
    #secap_id = "91a41534-7597-4975-8763-0642ef98c864"
    check_secap_readiness(secap_id)

    # new_node_name = new_node["name"]
    # new_node["id"] = "0"  # TODO get from orchestrator the id of the newly created firewall
    # logger.info(f"new firewall node {new_node_name} deployed")


def add_filtering_rules(node1, iptables_rule):

    logger.info("adding filtering rule to iptables instance")

    if node1["id"] == "-1":
        url='http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/api/v2/lcm/ns'  + '?tenant_id=' + TENANT_ORCHESTRATOR
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}

        raw_response = requests.get(url, headers=headers)
        response = json.loads(raw_response.text)

        logger.info("response code from orchestrator " + str(raw_response.status_code))
        logger.info("response from orchestrator: ")
        logger.info(response)

        if not raw_response.ok:
            logger.error("response headers from orchestrator " + str(raw_response.headers))
            logger.error("response text from orchestrator " + str(raw_response.text))
            return

        for secap in response.get("ns"):
            if secap.get("package").get("name") == node1["secap_type"]:
               node1["id"] = secap.get("id")
               break

    if check_secap_readiness(node1["id"]) or ENABLE_MANO_API == "0":
        send_action(node=node1,
                    payload={"action-name": "run", "action-params": {"cmd": iptables_rule["rule"]}},
                    action_name="Add filtering rule to iptables SC",
                    action_description="iptables SC reconfigured with command: " + iptables_rule["rule"])
    else:
        logger.error("Cannot add new rules, the security capability isn't operational")


def flush_filtering_rules(node1):

    logger.info("flushing filtering rules on iptables instance")
    if node1["id"] == "-1":
        url='http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/api/v2/lcm/ns'  + '?tenant_id=' + TENANT_ORCHESTRATOR
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}

        raw_response = requests.get(url, headers=headers)
        response = json.loads(raw_response.text)

        logger.info("response code from orchestrator " + str(raw_response.status_code))
        logger.info("response from orchestrator: ")
        logger.info(response)

        if not raw_response.ok:
            logger.error("response headers from orchestrator " + str(raw_response.headers))
            logger.error("response text from orchestrator " + str(raw_response.text))
            return

        for secap in response.get("ns"):
            if secap.get("package").get("name") == node1["secap_type"]:
               node1["id"] = secap.get("id")
               break

    # if check_secap_readiness(node1["id"]):

    send_action(node=node1,
                payload={"action-name": "run", "action-params": {"cmd": "iptables-save | grep -v RR-TOOL_GENERATED | "
                                                                        "iptables-restore"}},
                action_name="Flush rules on iptables SC",
                action_description="iptables SC reconfigured with command: iptables-save | grep -v "
                                "RR-TOOL_GENERATED | iptables-restore")

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

def send_action(node,
                payload,
                action_name,
                action_description,
                headers=None,
                base_url='http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/api/v2/lcm/ns/action?id=',
                component_type="Recommendation and Remediation",
                component_id="0"):

    # here node["id"] represents the id of the security capability (control) to which the new rule must be added

    if headers is None:
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    url = base_url + node["id"] + '&tenant_id=' + TENANT_ORCHESTRATOR + '&wait_for=NONE'
    if ENABLE_MANO_API == "1":
        r = requests.post(url, headers=headers, json=payload)
        logger.debug("request submitted to orchestrator URL: "+str(url))
        logger.debug("request submitted to orchestrator headers: "+str(headers))
        logger.debug("request submitted to orchestrator payload: "+str(payload))
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
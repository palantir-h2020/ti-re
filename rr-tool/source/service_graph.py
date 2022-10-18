from typing import Dict

from connectors import mano
from helpers.igraph_helper import *

from helpers.logging_helper import get_logger

logger = get_logger('service-graph')


def find_preceding_node_in_path(node, path):
    logger.info(msg=f"Searching node behind {node} in path " + str(path))
    preceding_node = None
    for index, item in enumerate(path):  # first find node to which node1 is connected
        if item == node:
            preceding_node = path[index + 1]
            break
    if preceding_node is None:
        raise Exception('No node connected to ' + node + ' found')
    return preceding_node


def generate_victim_attacker_graph():# -> [ig.Graph, Dict]:
    node_counters = {
        "firewall": 0,
        "switch": 0,
        "host": 2,
        "network_monitor": 0
    }

    gnet1 = ig.Graph(4)
    gnet1.vs["name"] = ["victim", "attacker", "backup_server"]
    gnet1.add_edges(
        [("victim", "attacker"), ("victim", "backup_server")])
    gnet1.vs["ipAddress"] = ["10.1.0.10", "1.2.3.4", settings.BACKUP_SERVER_IP]
    gnet1.vs["subnetMask"] = ["16", "16", "16"]
    gnet1.vs["nodeType"] = ["host", "attacker", "host"]
    return gnet1, node_counters


def generate_victim_firewall_attacker_graph():# -> [ig.Graph, Dict]:
    node_counters = {
        "firewall": 1,
        "switch": 0,
        "host": 2,
        "network_monitor": 0
    }

    gnet1 = ig.Graph(4)
    gnet1.vs["name"] = ["victim", "attacker", "border_firewall", "backup_server"]
    gnet1.add_edges(
        [("victim", "border_firewall"), ("border_firewall", "attacker"), ("border_firewall", "backup_server")])
    gnet1.vs["ipAddress"] = ["10.1.0.10", "1.2.3.4", "10.1.0.11", settings.BACKUP_SERVER_IP]
    gnet1.vs["subnetMask"] = ["16", "16", "16", "16"]
    gnet1.vs["nodeType"] = ["host", "attacker", "firewall", "host"]

    border_firewall_node = get_vertex_by_name(gnet1, "border_firewall")
    border_firewall_node["nodeType"] = "firewall"
    border_firewall_node["id"] = "910cad9d-ec96-44a5-85fb-b228d7e8da77"
    border_firewall_node["rules_level_4"] = []
    border_firewall_node["rules_level_7"] = []
    border_firewall_node["capabilities"] = ["level_4_filtering"]
    return gnet1, node_counters


class ServiceGraph:
    node_counters = {}

    def __init__(self):

        # TODO read landscape from file, initialize node counters accordingly
        self.sgraph, self.node_counters = generate_victim_attacker_graph()
        self.sgraph.vs["status"] = "on"  # set all nodes' status to on

        security_control_types = ["firewall"]
        if settings.RESET_SECURITY_CONTROLS_RULES_AT_STARTUP == "1":
            for node in self.sgraph.vs.select(nodeType_in=security_control_types):
                if node["nodeType"] == "firewall":
                    mano.flush_filtering_rules(node)

    def saveToGraphMl(self):
        self.sgraph.write_graphml("graph.xml")

    def plot(self):
        refreshAndSave(self.sgraph)

    def returnNodeName(self, node_identifier):
        # this function enables recipe functions to accept both node names and ip addresses as arguments

        try:
            nodeName = self.sgraph.vs.find(ipAddress=node_identifier)
            return nodeName["name"]
        except ValueError:
            return node_identifier

    def returnNodeIP(self, node_identifier):
        node1 = self.returnNodeName(node_identifier)
        node: ig.Vertex = self.sgraph.vs.find(node1)
        return node["ipAddress"]

    def changeNodeIP(self, node_name, new_node_ip):
        node: ig.Vertex = self.sgraph.vs.find(node_name)
        node["ipAddress"] = new_node_ip

    def list_paths(self, src_node, dst_node):  # return a list of node paths
        logger.info(msg="Searching for paths ...")
        srcNode = self.returnNodeName(srcNode)
        dstNode = self.returnNodeName(dstNode)
        paths = self.sgraph.get_all_simple_paths(srcNode, to=dstNode)
        logger.info(msg=f"Found {len(paths)} paths")
        node_paths = [ self.sgraph.vs[el]["name"] for el in paths ]
        logger.info(msg="Converted paths from node ids to node names")
        secondPositionNodes = set()
        for path in node_paths:
            secondPositionNodes.add(path[1])
        pruned_paths = []
        for nodeName in secondPositionNodes:
            for path in node_paths:
                if path[1] == nodeName:
                    pruned_paths.append(path)
                    break
        logger.info(msg="""Pruned equivalent paths, that is consider only
                        paths with different nodes attached to the srcNode""")
        return pruned_paths

    def find_node_in_path(self, path, node_type, capabilities):  # return node name
        logger.info(msg=f"Searching for a node of {node_type} type in this path: {path} ...")
        for el1 in path:
            node: ig.Vertex = self.sgraph.vs.find(el1)
            if node["nodeType"] == node_type:
                # logger.info(node)
                # logger.info(node["capabilities"])
                checkRequestedCapabilities = all(el2 in node["capabilities"] for el2 in capabilities)
                if checkRequestedCapabilities:
                    logger.info(
                        msg=f"Found node named {node['name']} of {node_type} type in the path with {capabilities}")
                    return node["name"]
        logger.info(msg=f"No node of {node_type} type found in the path with {capabilities}")
        return "Not found"

    def add_node(self, node1_name_or_ip, node2_name_or_ip, node_type):  # add node between node1 and node2

        node1_name = self.returnNodeName(node1_name_or_ip)
        node2_name = self.returnNodeName(node2_name_or_ip)

        logger.info(msg=f"Adding a node of type {node_type} between {node1_name} and {node2_name} ...")
        newNodeName = f"{node_type}{self.node_counters[node_type]}"

        newNode = add_vertex_between_vertices(self.sgraph, node1_name, newNodeName, node2_name)
        self.node_counters[node_type] += 1

        logger.info(msg=f"Added node of type {node_type} between {node1_name} and {node2_name}")

        newNode["nodeType"] = node_type
        mano.addNode(newNode, node_type)

        logger.debug(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_firewall(self, node1_name_or_ip, path, capabilities):  # add firewall behind "node" on the "path"

        node1_name = self.returnNodeName(node1_name_or_ip)
        logger.info(msg=f"Adding a firewall node behind {node1_name} ...")
        node2_name = find_preceding_node_in_path(node1_name, path)
        newNodeName = f"firewall{self.node_counters['firewall']}"

        new_node = add_vertex_between_vertices(self.sgraph, node1_name, newNodeName, node2_name)
        self.node_counters["firewall"] += 1

        new_node["nodeType"] = "firewall"
        new_node["rules_level_4"] = []
        new_node["rules_level_7"] = []
        new_node["capabilities"] = capabilities
        mano.addFirewall(new_node, path, capabilities)

        logger.info(msg=f"Added firewall between {node1_name} and {node2_name}")

        logger.debug(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_filtering_rules(self, node_name_or_ip, rules):

        node_name = self.returnNodeName(node_name_or_ip)
        logger.info(msg=f"Adding new rules to {node_name} ...")

        node: ig.Vertex = self.sgraph.vs.find(node_name)
        logger.info(msg=f"Got reference to {node_name}")

        for rule in rules:
            if rule["type"] == "level_4_filtering":
                if "level_4_filtering" in node["capabilities"]:
                    node["rules_level_4"].append(rule)
                    mano.add_filtering_rules(node, rule)
                    logger.info(msg=f"Added new level 4 rule to {node_name}: {rule}")
                else:
                    logger.info("This firewall doesn't support level 4 filtering!")
                    break
            else:
                if "level_7_filtering" in node["capabilities"]:
                    node["rules_level_7"].append(rule)
                    mano.add_filtering_rules(node, rule)
                    logger.info(msg=f"Added new level 7 rule to {node_name}: {rule}")
                else:
                    logger.info("This firewall doesn't support level 7 filtering!")
                    break
        logger.debug("Rules for firewall " + node['name'])
        i = 1
        for rule in node['rules_level_4']:
            logger.debug(node['name'] + ' rule #' + str(i) + " " + str(rule))
            i += 1

    def flush_filtering_rules(self, node1_name_or_ip):

        node1_name = self.returnNodeName(node1_name_or_ip)
        logger.info(msg=f"flushing rules on {node1_name} ...")

        node: ig.Vertex = self.sgraph.vs.find(node1_name)
        logger.info(msg=f"Got reference to {node1_name}")

        if "level_4_filtering" in node["capabilities"]:
            node["rules_level_4"] = []
        elif "level_7_filtering" in node["capabilities"]:
            node["rules_level_7"] = []
        mano.flush_filtering_rules(node)
        logger.debug("Rules for firewall " + node['name'])

    def get_filtering_rules(self, node_name_or_ip, level):
        node_name = self.returnNodeName(node_name_or_ip)
        node: ig.Vertex = self.sgraph.vs.find(node_name)
        return node["rules_level_" + str(level)]

    def add_dns_policy(self, domain, rule_type):

        logger.info(msg="Adding new rule to dns_server ...")
        rule = {"domain": domain, "action": rule_type}
        node1 = "dns_server"
        node: ig.Vertex = self.sgraph.vs.find(node1)
        logger.info(msg=f"Got reference to {node1}")
        node["dns_rules"].append(rule)
        logger.info(msg=f"Added new rule to {node1}: {rule}")

        logger.info(node)
        mano.add_dns_policy(domain, rule_type)

    def shutdown(self, node_name_or_ip):
        node_name = self.returnNodeName(node_name_or_ip)
        logger.info(msg=f"Shutting down {node_name} ...")

        refreshAndSave(self.sgraph)
        node: ig.Vertex = self.sgraph.vs.find(node_name)
        logger.info(msg=f"Got reference to {node_name}")
        node["status"] = "off"
        logger.info(msg=f"Set status of {node_name} to off")
        refreshAndSave(self.sgraph)
        mano.shutdown(node_name)

    def isolate(self, node_name_or_ip):
        node_name = self.returnNodeName(node_name_or_ip)
        logger.info(msg=f"Disconnecting all interfaces of {node_name} ...")

        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.es.select(_source=node_name))
        logger.info(msg=f"Deleted all edges from {node_name}")
        refreshAndSave(self.sgraph)
        mano.isolate(node_name)

    def add_honeypot(self, vulnerability):

        logger.info(msg="Adding a new honeypot node to the honey net ...")
        refreshAndSave(self.sgraph)
        self.node_counters["host"] += 1
        newNodeName = f"host{self.node_counters['host']}"
        node = self.sgraph.add_vertex(name=newNodeName, nodeType="honeypot")
        logger.info(msg="Added honeypot node to graph")
        if "vulnerabilityList" in node.attributes() and node["vulnerabilityList"] is not None:
            node["vulnerabilityList"] += f"/{vulnerability}"
        else:
            node["vulnerabilityList"] = vulnerability
        logger.info(msg="Added vulnerability list to honeypot node")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(newNodeName, "switch_honeyNet")])
        logger.info(msg="Added edge between honeypot and honey net switch")
        refreshAndSave(self.sgraph)
        mano.add_honeypot(vulnerability)

        # logger.info(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_network_monitor(self, node1_name_or_ip, path):  # add network monitor behind "node" on the "path"
        node1_name = self.returnNodeName(node1_name_or_ip)
        logger.info(msg=f"Adding network monitor node behind {node1_name} in this path {path} ...")

        node2_name = find_preceding_node_in_path(node1_name, path)
        newNodeName = f"network_monitor{self.node_counters['network_monitor']}"

        new_node = add_vertex_between_vertices(self.sgraph, node1_name, newNodeName, node2_name)
        self.node_counters["network_monitor"] += 1

        logger.debug(self.sgraph.vs.find(newNodeName).attributes())

        logger.info(msg="Added network monitor node to graph")
        mano.add_network_monitor(new_node, path)

        return newNodeName

    def move(self, node_name_or_ip, net):  # moves a node to another location
        node_name = self.returnNodeName(node_name_or_ip)
        logger.info(msg=f"Moving {node_name} to {net} ...")

        if net == "reconfiguration_net":
            switch = "switch_reconfigNet"
        else:
            raise Exception('Unknown network ' + net)
        node_name = self.returnNodeName(node_name)
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.es.select(_source=node_name))
        logger.info(msg=f"Deleted all edges from {node_name}")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node_name, switch)])
        logger.info(msg=f"Added edge from {node_name} to {switch}")
        refreshAndSave(self.sgraph)
        logger.debug(self.sgraph.vs.find(node_name).attributes())
        mano.move(node_name, net)


if __name__ == "__main__":
    pass

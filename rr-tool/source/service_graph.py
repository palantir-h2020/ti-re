# import os
# import tempfile
# from pathlib import Path
# import matplotlib.pyplot as plt
# import matplotlib.image as mpimg

import igraph as ig

import settings
from connectors import mano
from helpers.igraph_helper import *

from helpers.logging_helper import get_logger

logger = get_logger('service-graph')



class ServiceGraph:
    node_counters = {
        "firewall": 1,
        "switch": 0,
        "host": 2,
        "network_monitor": 0
    }

    def __init__(self):

        # TODO read landscape from file, initialize node counters accordingly
        gnet1 = ig.Graph(4)
        gnet1.vs["name"] = ["victim", "attacker", "border_firewall", "backup_server"]
        gnet1.add_edges(
            [("victim", "border_firewall"), ("border_firewall", "attacker"), ("border_firewall", "backup_server")])
        gnet1.vs["ipAddress"] = ["10.1.0.10", "1.2.3.4", "10.1.0.11", settings.BACKUP_SERVER_IP]
        gnet1.vs["subnetMask"] = ["16", "16", "16", "16"]
        gnet1.vs["nodeType"] = ["host", "firewall", "attacker", "host"]

        self.sgraph: ig.Graph = gnet1

        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["nodeType"] = "firewall"
        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["rules_level_4"] = []
        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["rules_level_7"] = []
        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["capabilities"] = ["level_4_filtering"]
        self.sgraph.vs["status"] = "on"  # set all nodes' status to on

    def saveToGraphMl(self):
        self.sgraph.write_graphml("graph.xml")

    def plot(self):
        refreshAndSave(self.sgraph)

    def returnNodeName(self, node_identifier):
        # this is a utility function used to quickly address the issue of accepting both node names and
        # ip addresses arguments given to functions in the recipes

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
        src_node = self.returnNodeName(src_node)
        dst_node = self.returnNodeName(dst_node)
        paths = self.sgraph.get_all_simple_paths(src_node, to=dst_node)
        logger.info(msg=f"Found {len(paths)} paths")
        node_paths = [self.sgraph.vs[el]["name"] for el in paths]
        logger.info(msg="Converted paths from node ids to node names")
        return node_paths

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

    def add_node(self, node1, node2, node_type):  # add node between node1 and node2

        node1 = self.returnNodeName(node1)
        node2 = self.returnNodeName(node2)

        logger.info(msg=f"Adding a node of type {node_type} between {node1} and {node2} ...")
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.get_eid(node1, node2))
        logger.info(msg=f"Removed edge from {node1} to {node2}")
        refreshAndSave(self.sgraph)
        self.node_counters[node_type] += 1
        newNodeName = f"{node_type}{self.node_counters[node_type]}"
        self.sgraph.add_vertex(name=newNodeName, nodeType=node_type)
        logger.info(msg=f"Added node of type {node_type} to graph named {newNodeName}")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
        logger.info(msg=f"Added an edge between {node1} and {newNodeName}")
        logger.info(msg=f"Added an edge between {newNodeName} and {node2}")
        refreshAndSave(self.sgraph)
        mano.addNode(node1, node_type)

        # logger.info(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_firewall(self, node1, path, capabilities):  # add firewall behind "node" on the "path"

        logger.info(msg=f"Adding a firewall node behind {node1} ...")
        node1 = self.returnNodeName(node1)
        for index, item in enumerate(path):  # first find node to which node1 is connected
            if item == node1:
                node2 = path[index + 1]
                break

        logger.info(msg=f"Searching node behind {node1}")
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.get_eid(node1, node2))
        logger.info(msg=f"Deleted edge between {node1} and {node2}")
        refreshAndSave(self.sgraph)
        self.node_counters["firewall"] += 1
        newNodeName = f"firewall{self.node_counters['firewall']}"
        self.sgraph.add_vertex(name=newNodeName, nodeType="firewall")
        self.sgraph.vs[self.sgraph.vs.find(newNodeName).index]["rules_level_4"] = []
        self.sgraph.vs[self.sgraph.vs.find(newNodeName).index]["rules_level_7"] = []
        self.sgraph.vs[self.sgraph.vs.find(newNodeName).index]["capabilities"] = capabilities
        logger.info(msg="Added firewall node to graph")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
        logger.info(msg=f"Added an edge between {node1} and {newNodeName}")
        logger.info(msg=f"Added an edge between {newNodeName} and {node2}")
        refreshAndSave(self.sgraph)
        mano.addFirewall(newNodeName, path, capabilities)

        # logger.info(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_filtering_rules(self, node1, rules):

        logger.info(msg=f"Adding new rules to {node1} ...")

        node1 = self.returnNodeName(node1)
        node: ig.Vertex = self.sgraph.vs.find(node1)
        logger.info(msg=f"Got reference to {node1}")

        for rule in rules:
            if rule["type"] == "level_4_filtering":
                if "level_4_filtering" in node["capabilities"]:
                    node["rules_level_4"].append(rule)
                    mano.add_filtering_rules(node, rule)
                    logger.info(msg=f"Added new level 4 rule to {node1}: {rule}")
                else:
                    logger.info("This firewall doesn't support level 4 filtering!")
                    break
            else:
                if "level_7_filtering" in node["capabilities"]:
                    node["rules_level_7"].append(rule)
                    mano.add_filtering_rules(node, rule)
                    logger.info(msg=f"Added new level 7 rule to {node1}: {rule}")
                else:
                    logger.info("This firewall doesn't support level 7 filtering!")
                    break
        logger.debug("Rules for firewall " + node['name'])
        i = 1
        for rule in node['rules_level_4']:
            logger.debug(node['name'] + ' rule #' + str(i) + " " + str(rule))
            i += 1

    def get_filtering_rules(self, node_name, level):
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

    def shutdown(self, node1):

        logger.info(msg=f"Shutting down {node1} ...")

        node1 = self.returnNodeName(node1)
        refreshAndSave(self.sgraph)
        node: ig.Vertex = self.sgraph.vs.find(node1)
        logger.info(msg=f"Got reference to {node1}")
        node["status"] = "off"
        logger.info(msg=f"Set status of {node1} to off")
        refreshAndSave(self.sgraph)
        mano.shutdown(node1)

    def isolate(self, node1):

        logger.info(msg=f"Disconnecting all interfaces of {node1} ...")

        node1 = self.returnNodeName(node1)
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.es.select(_source=node1))
        logger.info(msg=f"Deleted all edges from {node1}")
        refreshAndSave(self.sgraph)
        mano.isolate(node1)

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

    def add_network_monitor(self, node1, path):  # add network monitor behind "node" on the "path"

        logger.info(msg=f"Adding network monitor node behind {node1} in this path {path} ...")

        node1 = self.returnNodeName(node1)
        for index, item in enumerate(path):  # first find node to which node1 is connected
            if item == node1:
                node2 = path[index + 1]
                break

        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.get_eid(node1, node2))
        logger.info(msg=f"Deleted edge between {node1} and {node2}")
        refreshAndSave(self.sgraph)
        self.node_counters["network_monitor"] += 1
        newNodeName = f"network_monitor{self.node_counters['network_monitor']}"
        self.sgraph.add_vertex(name=newNodeName, nodeType="network_monitor")
        logger.info(msg="Added netowork monitor node to graph")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
        logger.info(msg=f"Added an edge between {node1} and {newNodeName}")
        logger.info(msg=f"Added an edge between {newNodeName} and {node2}")
        refreshAndSave(self.sgraph)
        # logger.info(self.sgraph.vs.find(newNodeName).attributes())
        mano.add_network_monitor(newNodeName, path)

        return newNodeName

    def move(self, node1, net):  # moves a node to another location

        logger.info(msg=f"Moving {node1} to {net} ...")

        if net == "reconfiguration_net":
            switch = "switch_reconfigNet"
        node1 = self.returnNodeName(node1)
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.es.select(_source=node1))
        logger.info(msg=f"Deleted all edges from {node1}")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, switch)])
        logger.info(msg=f"Added edge from {node1} to {switch}")
        refreshAndSave(self.sgraph)
        # logger.info(self.sgraph.vs.find(newNodeName).attributes())
        mano.move(node1, net)


if __name__ == "__main__":
    pass

import igraph as ig
import logging
import manoAPI

logging.basicConfig(level=logging.DEBUG)

globalCounters = {
    "firewall": 3,
    "switch": 2,
    "host": 12,
    "network_monitor": 0
}

visual_style = {}
visual_style["vertex_size"] = 10
visual_style["vertex_label"] = None
visual_style["vertex_label_size"] = 15
visual_style["vertex_label_dist"] = 3
visual_style["bbox"] = (800, 800)
visual_style["edge_width"] = 0.5
visual_style["edge_label_size"] = 15
visual_style["margin"] = 100

def colorVertices(graph):
    for vertex in graph.vs:
        if vertex["nodeType"] == "firewall":
            vertex["color"] = "red"
        elif vertex["nodeType"] == "host":
            vertex["color"] = 'black'
        elif vertex["nodeType"] == "switch":
            vertex["color"] = "blue"
        elif vertex["nodeType"] == "honeypot":
            vertex["color"] = "green"
        elif vertex["nodeType"] == "network_monitor":
            vertex["color"] = "yellow"
        elif vertex["nodeType"] == "gateway":
            vertex["color"] = "black"

def shapeVertices(graph):
    for vertex in graph.vs:
        if vertex["status"] == "off":
            vertex["shape"] = "circle"
        else:
            vertex["shape"] = "rectangle"

def refreshPlot(graph):
    colorVertices(graph)
    shapeVertices(graph)
    visual_style["vertex_label"] = graph.vs["name"]
    visual_style["vertex_color"] = graph.vs["color"]

def refreshAndPlot(graph):
    refreshPlot(graph)
    ig.plot(graph, **visual_style)

def refreshAndSave(graph):
    if not hasattr(refreshAndSave, "counter"):
        refreshAndSave.counter = 0
    refreshPlot(graph)
    ig.plot(graph,
            target=f'\tmp\graph{refreshAndSave.counter}.png',
            **visual_style)
    refreshAndSave.counter += 1

gnet1 = ig.Graph(4)
gnet1.vs["name"] = ["host1", "host2", "host3", "switch1"]
gnet1.add_edges([("host1", "switch1"), ("host2", "switch1"), ("host3", "switch1")])
gnet1.vs["ipAddress"] = ["10.1.0.10", "10.1.0.11", "10.1.0.12", None]
gnet1.vs["subnetMask"] = ["16", "16", "16", None]
gnet1.vs["nodeType"] = ["host", "host", "host", "switch"]

gnet2 = ig.Graph(4)
gnet2.vs["name"] = ["host4", "host5", "host6", "switch2"]
gnet2.add_edges([("host4", "switch2"), ("host5", "switch2"), ("host6", "switch2")])
gnet2.vs["ipAddress"] = ["10.2.0.10", "10.2.0.11", "10.2.0.12", None]
gnet2.vs["subnetMask"] = ["16", "16", "16", None]
gnet2.vs["nodeType"] = ["host", "host", "host", "switch"]

gnet3 = ig.Graph(4)
gnet3.vs["name"] = ["host7", "host8", "host9", "switch_honeyNet"]
gnet3.add_edges([("host7", "switch_honeyNet"), ("host8", "switch_honeyNet"), ("host9", "switch_honeyNet")])
gnet3.vs["ipAddress"] = ["10.3.0.10", "10.3.0.11", "10.3.0.12", None]
gnet3.vs["subnetMask"] = ["16", "16", "16", None]
gnet3.vs["nodeType"] = ["honeypot", "honeypot", "honeypot", "switch"]

gnet4 = ig.Graph(4)
gnet4.vs["name"] = ["host10", "host11", "host12", "switch_dmz"]
gnet4.add_edges([("host10", "switch_dmz"), ("host11", "switch_dmz"), ("host12", "switch_dmz")])
gnet4.vs["ipAddress"] = ["10.4.0.10", "10.4.0.11", "10.4.0.12", None]
gnet4.vs["subnetMask"] = ["16", "16", "16", None]
gnet4.vs["nodeType"] = ["host", "host", "host", "switch"]

sgraph: ig.Graph = gnet1.union([gnet2, gnet3, gnet4]) # specify type to fix code suggestions on that variable

firewall = sgraph.add_vertices(["switch_reconfigNet",
                                                "firewall1",
                                                "firewall2",
                                                "firewall3",
                                                "border_firewall",
                                                "gateway",
                                                "attacker"])

sgraph.vs[sgraph.vs.find("switch_reconfigNet").index]["nodeType"] = "switch"
sgraph.vs[sgraph.vs.find("firewall1").index]["nodeType"] = "firewall"
sgraph.vs[sgraph.vs.find("firewall2").index]["nodeType"] = "firewall"
sgraph.vs[sgraph.vs.find("firewall3").index]["nodeType"] = "firewall"
sgraph.vs[sgraph.vs.find("firewall1").index]["rules_level_4"] = []
sgraph.vs[sgraph.vs.find("firewall2").index]["rules_level_4"] = []
sgraph.vs[sgraph.vs.find("firewall3").index]["rules_level_4"] = []
sgraph.vs[sgraph.vs.find("firewall1").index]["rules_level_7"] = []
sgraph.vs[sgraph.vs.find("firewall2").index]["rules_level_7"] = []
sgraph.vs[sgraph.vs.find("firewall3").index]["rules_level_7"] = []
sgraph.vs[sgraph.vs.find("firewall1").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
sgraph.vs[sgraph.vs.find("firewall2").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
sgraph.vs[sgraph.vs.find("firewall3").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
sgraph.vs[sgraph.vs.find("border_firewall").index]["nodeType"] = "firewall"
sgraph.vs[sgraph.vs.find("border_firewall").index]["rules_level_4"] = []
sgraph.vs[sgraph.vs.find("border_firewall").index]["rules_level_7"] = []
sgraph.vs[sgraph.vs.find("border_firewall").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
sgraph.vs[sgraph.vs.find("gateway").index]["nodeType"] = "gateway"
sgraph.vs[sgraph.vs.find("attacker").index]["nodeType"] = "attacker"

sgraph.add_edge(sgraph.vs.find(name="switch2"), sgraph.vs.find(name="switch_reconfigNet"))
sgraph.add_edge(sgraph.vs.find(name="switch1"), sgraph.vs.find(name="firewall1"))
sgraph.add_edge(sgraph.vs.find(name="switch_reconfigNet"), sgraph.vs.find(name="firewall2"))
sgraph.add_edge(sgraph.vs.find(name="switch_honeyNet"), sgraph.vs.find(name="firewall3"))
sgraph.add_edge("firewall1", "border_firewall")
sgraph.add_edge("firewall2", "border_firewall")
sgraph.add_edge("firewall3", "border_firewall")
sgraph.add_edge("switch_dmz", "border_firewall")
sgraph.add_edge("border_firewall", "gateway")
sgraph.add_edge("gateway", "attacker")
sgraph.vs["status"] = "on"

def returnNodeName(nodeIdentifier):
    # this is a utility function used to quickly address the issue of accepting both node names and
    # ip addresses arguments given to functions in the recipes

    try:
        nodeName = sgraph.vs.find(ipAddress=nodeIdentifier)
        return nodeName["name"]
    except ValueError:
        return nodeIdentifier

def list_paths(srcNode, dstNode): # return a list of node paths
    logging.info(msg="Searching for paths ...")
    srcNode = returnNodeName(srcNode)
    dstNode = returnNodeName(dstNode)
    paths = sgraph.get_all_simple_paths(srcNode, to=dstNode)
    logging.info(msg=f"Found {len(paths)} paths")
    node_paths = [ sgraph.vs[el]["name"] for el in paths ]
    logging.info(msg="Converted paths from node ids to node names")
    return node_paths

def find_node_in_path(path, nodeType, capabilities): # return node name
    logging.info(msg=f"Searching for a node of {nodeType} type in this path: {path} ...")
    for el1 in path:
        node: ig.Vertex = sgraph.vs.find(el1)
        if node["nodeType"] == nodeType:
            checkRequestedCapabilities = all(el2 in node["capabilities"] for el2 in capabilities)
            if checkRequestedCapabilities:
                logging.info(msg=f"Found node named {node['name']} of {nodeType} type in the path with {capabilities}")
                return node["name"]
    logging.info(msg=f"No node of {nodeType} type found in the path with {capabilities}")
    return "Not found"

def add_node(node1, node2, nodeType): # add node between node1 and node2

    node1 = returnNodeName(node1)
    node2 = returnNodeName(node2)

    logging.info(msg=f"Adding a node of type {nodeType} between {node1} and {node2} ...")
    refreshAndSave(sgraph)
    sgraph.delete_edges(sgraph.get_eid(node1, node2))
    logging.info(msg=f"Removed edge from {node1} to {node2}")
    refreshAndSave(sgraph)
    globalCounters[nodeType] += 1
    newNodeName = f"{nodeType}{globalCounters[nodeType]}"
    sgraph.add_vertex(name=newNodeName, nodeType=nodeType)
    logging.info(msg=f"Added node of type {nodeType} to graph named {newNodeName}")
    refreshAndSave(sgraph)
    sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
    logging.info(msg=f"Added an edge between {node1} and {newNodeName}")
    logging.info(msg=f"Added an edge between {newNodeName} and {node2}")
    refreshAndSave(sgraph)
    manoAPI.addNode(node1, nodeType)

    return newNodeName

def add_firewall(node1, path, capabilities): # add firewall behind "node" on the "path"

    logging.info(msg=f"Adding a firewall node behind {node1} ...")
    node1 = returnNodeName(node1)
    for index, item in enumerate(path): # first find node to which node1 is connected
        if item == node1:
            node2 = path[index+1]
            break


    logging.info(msg=f"Searching node behind {node1}")
    refreshAndSave(sgraph)
    sgraph.delete_edges(sgraph.get_eid(node1, node2))
    logging.info(msg=f"Deleted edge between {node1} and {node2}")
    refreshAndSave(sgraph)
    globalCounters["firewall"] += 1
    newNodeName = f"firewall{globalCounters['firewall']}"
    sgraph.add_vertex(name=newNodeName, nodeType="firewall")
    sgraph.vs[sgraph.vs.find(newNodeName).index]["rules_level_4"] = []
    sgraph.vs[sgraph.vs.find(newNodeName).index]["rules_level_7"] = []
    sgraph.vs[sgraph.vs.find(newNodeName).index]["capabilities"] = capabilities
    logging.info(msg="Added firewall node to graph")
    refreshAndSave(sgraph)
    sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
    logging.info(msg=f"Added an edge between {node1} and {newNodeName}")
    logging.info(msg=f"Added an edge between {newNodeName} and {node2}")
    refreshAndSave(sgraph)


    return newNodeName

def add_filtering_rules(node1, rules):

    logging.info(msg=f"Adding new rules to {node1} ...")

    node1 = returnNodeName(node1)
    node: ig.Vertex = sgraph.vs.find(node1)
    logging.info(msg=f"Got reference to {node1}")
    for rule in rules:
        if rule["level"] == 4:
            if "level_4_filtering" in node["capabilities"]:
                node["rules_level_4"].append(rule)
                logging.info(msg=f"Added new level 4 rule to {node1}")
            else:
                logging.info("This firewall doesn't support level 4 filtering!")
                break
        else:
            if "level_7_filtering" in node["capabilities"]:
                node["rules_level_7"].append(rule)
                logging.info(msg=f"Added new level 7 rule to {node1}")
            else:
                logging.info("This firewall doesn't support level 7 filtering!")
                break
    print(node)

def shutdown(node1):

    logging.info(msg=f"Sutting down {node1} ...")

    node1 = returnNodeName(node1)
    refreshAndSave(sgraph)
    node: ig.Vertex = sgraph.vs.find(node1)
    logging.info(msg=f"Got reference to {node1}")
    node["status"] = "off"
    logging.info(msg=f"Set status of {node1} to off")
    refreshAndSave(sgraph)

def isolate(node1):

    logging.info(msg=f"Disconnecting all interfaces of {node1} ...")

    node1 = returnNodeName(node1)
    refreshAndSave(sgraph)
    sgraph.delete_edges(sgraph.es.select(_source=node1))
    logging.info(msg=f"Deleted all edges from {node1}")
    refreshAndSave(sgraph)

def add_honeypot(vulnerability):

    logging.info(msg="Adding a new honeypot to the honey net ...")
    refreshAndSave(sgraph)
    globalCounters["host"] += 1
    newNodeName = f"host{globalCounters['host']}"
    node = sgraph.add_vertex(name=newNodeName, nodeType="honeypot")
    logging.info(msg="Added honeypot node to graph")
    if "vulnerabilityList" in node.attributes(): #todo check if this works
        node["vulnerabilityList"] += f"/{vulnerability}"
    else:
        node["vulnerabilityList"] = vulnerability
    logging.info(msg="Added vulnerability list to honeypot node")
    refreshAndSave(sgraph)
    sgraph.add_edges([(newNodeName, "switch_honeyNet")])
    logging.info(msg="Added edge between honeypot and honey net switch")
    refreshAndSave(sgraph)

    return newNodeName

def add_network_monitor(node1, path): # add network monitor behind "node" on the "path"

    logging.info(msg=f"Adding network monitor behind {node1} in this path {path} ...")

    node1 = returnNodeName(node1)
    for index, item in enumerate(path): # first find node to which node1 is connected
        if item == node1:
            node2 = path[index+1]
            break

    refreshAndSave(sgraph)
    sgraph.delete_edges(sgraph.get_eid(node1, node2))
    logging.info(msg=f"Deleted edge between {node1} and {node2}")
    refreshAndSave(sgraph)
    globalCounters["network_monitor"] += 1
    newNodeName = f"network_monitor{globalCounters['network_monitor']}"
    sgraph.add_vertex(name=newNodeName, nodeType="network_monitor")
    logging.info(msg="Added netowork monitor node to graph")
    refreshAndSave(sgraph)
    sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
    logging.info(msg=f"Added an edge between {node1} and {newNodeName}")
    logging.info(msg=f"Added an edge between {newNodeName} and {node2}")
    refreshAndSave(sgraph)

    return newNodeName

def move(node1, net): # moves a node to another location

    logging.info(msg=f"Moving {node1} to {net} ...")

    if net == "reconfiguration_net":
        switch = "switch_reconfigNet"
    node1 = returnNodeName(node1)
    refreshAndSave(sgraph)
    sgraph.delete_edges(sgraph.es.select(_source=node1))
    logging.info(msg=f"Deleted all edges from {node1}")
    refreshAndSave(sgraph)
    sgraph.add_edges([(node1, switch)])
    logging.info(msg=f"Added edge from {node1} to {switch}")
    refreshAndSave(sgraph)
    

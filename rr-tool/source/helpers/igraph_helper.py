import igraph as ig

import settings
from helpers.logging_helper import get_logger
logger = get_logger('igraph-helper')

visual_style = {"vertex_size": 10, "vertex_label": None, "vertex_label_size": 15, "vertex_label_dist": 3,
                "bbox": (800, 800), "edge_width": 0.5, "edge_label_size": 15, "margin": 100}


# visual_style["vertex_shape"] = "rectangle"
# don't need this, now the shape is set before saving the plot to file according to the node status


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
        elif vertex["nodeType"] == "dns_server":
            vertex["color"] = "violet"
        elif vertex["nodeType"] == "gateway":
            vertex["color"] = "black"


def shapeVertices(graph):
    for vertex in graph.vs:
        if vertex["status"] == "off":
            vertex["shape"] = "circle"
        else:
            vertex["shape"] = "rectangle"


def refreshPlot1(graph):
    """Refreshes graph and sets nodes label to their name"""
    colorVertices(graph)
    shapeVertices(graph)
    visual_style["vertex_label"] = graph.vs["name"]


def refreshAndPlot1(graph):
    """Refreshes graph and plots to screen"""
    refreshPlot1(graph)
    ig.plot(graph, **visual_style)


def refreshAndSave1(graph):
    """Refreshes graph and saves it as image in png format"""
    logger.info(msg="Plotting with refreshAndSave")
    if not hasattr(refreshAndSave1, "counter"):
        refreshAndSave1.counter = 0
    refreshPlot1(graph)
    ig.plot(graph,
            target=f'{settings.IGRAPH_PICTURES_OUTPUT_FOLDER}/graph{refreshAndSave1.counter}.png',
            **visual_style)
    refreshAndSave1.counter += 1


def refreshPlot2(graph):
    """Refreshes graph and sets nodes label to their name, plus the node ip if they have one"""
    colorVertices(graph)
    shapeVertices(graph)
    labels = []
    for vertex in graph.vs:
        if "ipAddress" in vertex.attributes() and vertex["ipAddress"] is not None:
            labels.append(str(vertex["name"] + "\n" + vertex["ipAddress"]))
        else:
            labels.append(str(vertex["name"]))
    visual_style["vertex_label"] = labels


def refreshAndSave2(graph):
    """Refreshes graph and saves it as image in png format, node names will show their ip address if they have one"""
    logger.info(msg="Plotting with refreshAndSave2")
    if not hasattr(refreshPlot2, "counter"):
        refreshPlot2.counter = 0
    refreshPlot2(graph)
    ig.plot(graph,
            target=f'{settings.IGRAPH_PICTURES_OUTPUT_FOLDER}/graph{refreshPlot2.counter}.png',
            **visual_style)
    refreshPlot2.counter += 1


def refreshAndSave(graph):
    # CONFIGURATION -> uncomment the one to be used
    # refreshAndSave1(graph)
    # refreshAndSave2(graph)
    del graph
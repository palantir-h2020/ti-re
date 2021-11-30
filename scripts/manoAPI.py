import logging

def addNode(nodeName, nodeType):
    logging.info("Calling MANO API")
    logging.info(f"node {nodeName} added!!")

def addRule(nodeName, rule):
    logging.info("Calling MANO API")
    print(f"rule added to {nodeName}!!")

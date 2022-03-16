import logging
import xml.etree.ElementTree as ET
import subprocess


def visit(root):
    for child in root:
        print(child.tag, child.attrib)
        visit(child)


def globalFind(root: ET.Element, item: str) -> ET.Element:
    """ Retrieves the first element with name `item`, found left discending
    recursively into the tree composed of children elements of the `root`"""

    result = root.find(item)
    if result is None:
        for child in root:
            result = globalFind(child, item)
            if result is not None:
                return result
    else:
        return result


def modifyElement(root: ET.Element, item: str, value: str):
    """ Sets the value of the first element called `item`, found using the globalFind function on the `root`
    element, to the value passed in `value`"""

    el = globalFind(root, item)
    el.text = value


def deleteElement(root: ET.Element, item: str):
    """ Sets the value of the first element called `item`, found using the globalFind function on the `root`
    element, to the value passed in `value`"""

    result = root.find(item)
    if result is None:
        for child in root:
            result = globalFind(child, item)
            if result is not None:
                child.remove(result)
                return child
    else:
        return result


# import xml.etree.ElementTree as ET
# tree = ET.parse('iptables_model.xml')
# root = tree.getroot()
# for child in root[0]:
#     print(child)

def getIptablesCommand(srcIp, dstIp, dstPort, proto, chain, action):
    tree = ET.parse('iptables_model.xml')
    root = tree.getroot()

    if proto == "":
        deleteElement(root, "ipProtocolTypeConditionCapability")
    else:
        modifyElement(root, "exactMatch", proto)
    modifyElement(root, "chain", chain)

    if dstPort == "":
        deleteElement(root, "destinationPortConditionCapability")
    else:
        dstPortElement = globalFind(root, "destinationPortConditionCapability")
        modifyElement(dstPortElement, "exactMatch", str(dstPort))

    if srcIp == "":
        deleteElement(root, "ipSourceAddressConditionCapability")
    else:
        srcIpElement = globalFind(root, "ipSourceAddressConditionCapability")
        modifyElement(srcIpElement, "address", srcIp)

    if dstIp == "":
        deleteElement(root, "ipDestinationAddressConditionCapability")
    else:
        dstIpElement = globalFind(root, "ipDestinationAddressConditionCapability")
        modifyElement(dstIpElement, "address", dstIp)

    # default action DENY
    if action != "" and action !="ALLOW" and action != "DENY":
        logging.error("iptables translator: Unsupported action "+action)
    if action == "ALLOW":
        actionElement = globalFind(root, "rejectActionCapability")
        actionElement.tag = 'acceptActionCapability'

    tree.write("iptables_input_for_translator.xml")

    code = subprocess.call(
        ['java', '-jar', 'newTranslator.jar', 'iptables.xsd', 'catalogue.xml', 'iptables_input_for_translator.xml',
         'iptables_output.txt'])
    if code != 0:
        raise Exception("Error during iptables rule translation")

    with open("./iptables_output.txt", "r", encoding='utf8') as file:
        return file.read().replace(' \n', '')


# def getIptablesFbmCommand(victimIp, backupServerIp, chain):
#     tree = ET.parse('iptables_model.xml')
#
#     for rule in tree.getroot().findall("rule"):
#         if rule.get("id") == 0:
#             modifyElement(rule, "rule", chain)
#             srcIpElement = globalFind(rule, "ipSourceAddressConditionCapability")
#             dstIpElement = globalFind(rule, "ipDestinationAddressConditionCapability")
#             modifyElement(srcIpElement, "address", victimIp)
#             modifyElement(dstIpElement, "address", backupServerIp)
#         elif rule.get("id") == 1:
#             modifyElement(rule, "rule", chain)
#             srcIpElement = globalFind(rule, "ipSourceAddressConditionCapability")
#             dstIpElement = globalFind(rule, "ipDestinationAddressConditionCapability")
#             modifyElement(srcIpElement, "address", backupServerIp)
#             modifyElement(dstIpElement, "address", victimIp)
#         elif rule.get("id") == 2:
#             modifyElement(rule, "rule", chain)
#             srcIpElement = globalFind(rule, "ipSourceAddressConditionCapability")
#             modifyElement(srcIpElement, "address", victimIp)
#         elif rule.get("id") == 3:
#             modifyElement(rule, "rule", chain)
#             dstIpElement = globalFind(rule, "ipDestinationAddressConditionCapability")
#             modifyElement(dstIpElement, "address", victimIp)
#         else:
#             logging.error("Malformed iptables_model_fbm.xml, aborting")
#             return
#
#     tree.write("iptables_input_for_translator.xml")
#
#     code = subprocess.call(
#         ['java', '-jar', 'newTranslator.jar', 'iptables.xsd', 'catalogue.xml', 'iptables_input_for_translator.xml',
#          'iptables_output.txt'])
#     if code != 0:
#         raise Exception("Error during iptables rule translation")
#
#     with open("./iptables_output.txt", "r", encoding='utf8') as file:
#         return file.read().replace(' \n', '')


if __name__ == "__main__":
    # tree = ET.parse('iptables_model.xml')
    # root = tree.getroot()
    # print(root.attrib)
    # visit(root)

    # modifyElement(root, "exactMatch", "UDP")
    # modifyElement(root, "chain", "FORWARD")
    # dstPortElement = globalFind(root, "destinationPortConditionCapability")
    # srcIpElement = globalFind(root, "ipSourceAddressConditionCapability")
    # dstIpElement = globalFind(root, "ipDestinationAddressConditionCapability")
    # modifyElement(dstPortElement, "exactMatch", "80")
    # modifyElement(srcIpElement, "address", "10.1.0.10")
    # modifyElement(dstIpElement, "address", "1.2.3.4")

    # tree.write("iptables_input_for_translator.xml")

    # with open("./output.txt", "r", encoding='utf8') as file:
    #         content = file.read()
    #         print(content)

    pass

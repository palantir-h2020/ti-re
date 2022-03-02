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

def modifyElement(root:ET.Element, item:str, value:str):
    """ Sets the value of the first element called `item`, found using the globalFind function on the `root`
    element, to the value passed in `value`"""

    el = globalFind(root, item)
    el.text = value


def getIptablesCommand(srcIp, dstIp, dstPort, proto, chain):

    tree = ET.parse('iptables_model.xml')
    root = tree.getroot()

    modifyElement(root, "exactMatch", proto)
    modifyElement(root, "chain", chain)
    dstPortElement = globalFind(root, "destinationPortConditionCapability")
    srcIpElement = globalFind(root, "ipSourceAddressConditionCapability")
    dstIpElement = globalFind(root, "ipDestinationAddressConditionCapability")
    modifyElement(dstPortElement, "exactMatch", str(dstPort))
    modifyElement(srcIpElement, "address", srcIp)
    modifyElement(dstIpElement, "address", dstIp)

    tree.write("iptables_input_for_translator.xml")

    code = subprocess.call(['java', '-jar', 'newTranslator.jar', 'iptables.xsd', 'catalogue.xml', 'iptables_input_for_translator.xml', 'iptables_output.txt'])
    if code != 0:
        raise Exception("Error during iptables rule translation")

    with open("./iptables_output.txt", "r", encoding='utf8') as file:
        return file.read().replace(' \n','')


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
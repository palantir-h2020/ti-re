import os
import subprocess

from helpers.xml_helper import *
from xml.etree import ElementTree

from helpers.logging_helper import get_child_logger

logger = get_child_logger('security-controls', 'iptables')


# noinspection PyUnusedLocal
def iptables_command_generator(rule, *args):
    for key in ["victimIP", "c2serversIP", "victimPort", "c2serversPort", "proto", "action"]:
        if key not in rule:
            rule[key] = ""

    generatedRule = getIptablesCommand(rule["victimIP"],
                                       rule["c2serversIP"],
                                       rule["victimPort"],
                                       rule["c2serversPort"],
                                       rule["proto"],
                                       "FORWARD",
                                       rule["action"])

    return generatedRule.replace("iptables -A FORWARD", "iptables -I FORWARD 1") + " -m comment --comment " \
                                                                                   "\"RR-TOOL_GENERATED\""


def getIptablesCommand(src_ip, dst_ip, src_port, dst_port, proto, chain, action):

    iptables_dir = os.path.dirname(os.path.realpath(__file__))
    tree = ElementTree.parse(iptables_dir + os.sep + "iptables_model.xml")
    root = tree.getroot()

    if proto == "":
        deleteElement(root, "ipProtocolTypeConditionCapability")
    else:
        modifyElement(root, "exactMatch", proto)
    modifyElement(root, "chain", chain)

    if src_port == "":
        deleteElement(root, "sourcePortConditionCapability")
    else:
        srcPortElement = globalFind(root, "sourcePortConditionCapability")
        modifyElement(srcPortElement, "exactMatch", str(src_port))

    if dst_port == "":
        deleteElement(root, "destinationPortConditionCapability")
    else:
        dstPortElement = globalFind(root, "destinationPortConditionCapability")
        modifyElement(dstPortElement, "exactMatch", str(dst_port))

    if src_ip == "":
        deleteElement(root, "ipSourceAddressConditionCapability")
    else:
        srcIpElement = globalFind(root, "ipSourceAddressConditionCapability")
        modifyElement(srcIpElement, "address", src_ip)

    if dst_ip == "":
        deleteElement(root, "ipDestinationAddressConditionCapability")
    else:
        dstIpElement = globalFind(root, "ipDestinationAddressConditionCapability")
        modifyElement(dstIpElement, "address", dst_ip)

    # default action DENY
    if action != "" and action != "ALLOW" and action != "DENY":
        logger.error("iptables translator: Unsupported action " + action)
    if action == "ALLOW":
        actionElement = globalFind(root, "rejectActionCapability")
        actionElement.tag = 'acceptActionCapability'

    tree.write(iptables_dir + os.sep + "iptables_input_for_translator.xml")

    # TODO validate translator input against iptables.xsd

    code = subprocess.call(
        ['java', '-jar',
         iptables_dir + os.sep + 'newTranslator.jar',
         iptables_dir + os.sep + 'iptables.xsd',
         iptables_dir + os.sep + 'catalogue.xml',
         iptables_dir + os.sep + 'iptables_input_for_translator.xml',
         iptables_dir + os.sep + 'iptables_output.txt'])
    if code != 0:
        raise Exception("Error during iptables rule translation")

    with open(iptables_dir + os.sep + "iptables_output.txt", "r", encoding='utf8') as file:
        return file.read().replace(' \n', '')

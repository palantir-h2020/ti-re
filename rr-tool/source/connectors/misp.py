import json
import urllib3
from typing import Tuple
from pymisp import PyMISP
from pymisp import MISPEvent, MISPAttribute, MISPObject, MISPTag
from pymisp.tools import GenericObjectGenerator
from pymisp.tools import stix
from uuid import uuid4
from datetime import datetime, time, date, timedelta
from helpers import stix_helper
from settings import ENABLE_PRIVATE_ARTIFACTS_SHARING

# this avoids showing insecure connection warnings in the logs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from helpers.logging_helper import get_logger

logger = get_logger("misp")


misp_url = "https://10.101.41.42:8081"
misp_key = "zfajFlj9sOQOZpL7jDFHunSEKU26r8LrxSeaFheY"

misp_verifycert = False
#days_from_today = 100

#https://pymisp.readthedocs.io/en/latest/tools.html#module-pymisp.tools.stix


# PyMISP tutorial
# https://github.com/MISP/PyMISP/blob/main/docs/tutorial/FullOverview.ipynb


# tag colours
# https://github.com/MISP/misp-taxonomies/blob/main/tlp/machinetag.json

def publish_on_misp_test():

    stix_report_json, stix_report_base64 = stix_helper.getSTIXReport_test()

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    event = MISPEvent()

    event.info = "This is my new MISP event"

    attribute1 = event.add_attribute(type="text",
                                    value=stix_report_json)

    attribute2 = event.add_attribute(type="text",
                                    value=stix_report_base64)

    attribute3 = event.add_attribute(type="ip-dst",
                                    value="1.1.1.1")

    # mitre tags: https://github.com/MISP/PyMISP/issues/479

    mitre_attack_pattern_tag =  'misp-galaxy:mitre-attack-pattern="AppCert DLLs - T1182'
    mitre_attack_pattern_tag2 =  'misp-galaxy:mitre-attack-pattern="Phishing - T1566'

    # A MITRE attack pattern tag can be appended both to the event and the event's attributes
    event.add_tag(mitre_attack_pattern_tag)
    attribute2.add_tag(mitre_attack_pattern_tag2)

    event = misp.add_event(event)

    logger.debug(f"Published test event on MISP")

def publish_on_misp(global_scope, stix_report_json, stix_report_base64, threat_type):

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    event = MISPEvent()

    organization_id = global_scope.get("organization_id")

    attribute1 = event.add_attribute(type="text",
                                    value=stix_report_json)
    attribute1.add_tag("JSON STIX 2.1 Report")

    attribute2 = event.add_attribute(type="text",
                                    value=stix_report_base64)
    attribute2.add_tag("Base64 STIX 2.1 Report")

    # MISP security playbook object schema and stix_coa -> misp object
    # https://github.com/MISP/misp-objects/blob/main/objects/security-playbook/definition.json
    # https://github.com/cyentific-rni/security-playbook-stix-misp-exchange

    playbook_object = MISPObject("security-playbook", standalone=False)
    playbook_object.comment = "Remediation playbook"
    # https://github.com/MISP/PyMISP/issues/437
    # playbook_object.add_attribute("playbook-file",
    #                             value=global_scope.get("cacao_playbook_json"))
    playbook_object.add_attribute("playbook-base64",
                                value=global_scope.get("cacao_playbook_base64"))
    playbook_object.add_attribute("playbook-standard",
                                value="CACAO")
    playbook_object.add_attribute("playbook-abstraction",
                                value="executable") # template
    playbook_object.add_attribute("description",
                                value="Just a CACAO playbook")
    playbook_object.add_attribute("playbook-type",
                                value=["remediation", "mitigation", "containment"])

    event.add_object(playbook_object)

    if threat_type == "unauthorized_access": # unauthorized_access attributes
        event.info = "Unauthorized access report"
        attacker_ip = global_scope.get("UnauthorizedAccessAlertSourceIp")
        impacted_host_ip = global_scope.get("UnauthorizedAccessAlertSourceIp")

        attribute3 = event.add_attribute(type="ip-dst",
                                    value=attacker_ip)

        if ENABLE_PRIVATE_ARTIFACTS_SHARING == "1":
            attribute3 = event.add_attribute(type="ip-src",
                                        value=impacted_host_ip)
            attribute3.add_tag("tlp:red")
            event.add_tag("tlp:red")

    elif threat_type == "ransomware": # ransomware specific attributes
        event.info = "Ransomware report"
        impacted_host_ip = global_scope.get("RansomwareAlertSourceIp")

        if ENABLE_PRIVATE_ARTIFACTS_SHARING == "1":
            # attribute3 = event.add_attribute(type="ip-dst",
            #                             value=impacted_host_ip)

            ip_object = MISPObject("domain-ip", standalone=False)
            ip_object.comment = "Victim host"
            ip_object.add_attribute("ip",
                                    value = impacted_host_ip)
            event.add_object(ip_object)

            event.add_tag("tlp:red")

    elif threat_type == "botnet": # botnet specific attributes
        event.info = "Botnet report"
        attacker_ip = global_scope.get("attacker_ip")
        c2serversPort = global_scope.get("c2serversPort")
        impacted_host_ip = global_scope.get("impacted_host_ip")
        stix_ioc_pattern = global_scope.get("stix_ioc_pattern")

        attribute3 = event.add_attribute(type="ip-dst",
                                    value=attacker_ip)

        if ENABLE_PRIVATE_ARTIFACTS_SHARING == "1":
            attribute3 = event.add_attribute(type="ip-src",
                                        value=impacted_host_ip)
            event.add_tag("tlp:red")

        # pattern object https://github.com/MISP/misp-objects/blob/main/objects/stix2-pattern/definition.json
        pattern_object = MISPObject("stix2-pattern", standalone=False)
        pattern_object.comment = "STIX 2.1 IoC pattern"
        pattern_object.add_attribute("version",
                                value = "stix 2.1")
        pattern_object.add_attribute("stix2-pattern",
                                value = stix_ioc_pattern)
        event.add_object(pattern_object)


    event = misp.add_event(event)

    logger.info(f"Published event on MISP")

    # attributeAsDict = [{'MyCoolAttribute': {'value': 'critical thing', 'type': 'text'}},
    #                {'MyCoolerAttribute': {'value': 'even worse',  'type': 'text'}}]
    # misp_object = GenericObjectGenerator('my-cool-template')
    # misp_object.generate_attributes(attributeAsDict)
    # # The parameters below are required if no template is provided.
    # misp_object.template_uuid = uuid4()
    # misp_object.templade_id = 1
    # misp_object.description = "foo"
    # setattr(misp_object, 'meta-category', 'bar')

    # dict_attr = {
    #     "type": "ip-dst",
    #     "value": "127.0.0.1",
    #     "category": "Network activity",
    #     "to_ids": False
    # }
    # json_attr = json.dumps(dict_attr)

    # attribute = MISPAttribute()
    # attribute.from_json(json_attr)
    # print(attribute)

    # event.add_object(misp_object)

    # with open("imddos.json") as misp_event_file:
    #     misp_event_json = json.load(misp_event_file)

    # json_string = json.dumps(misp_event_json)



    #print(misp_object.to_json())


    # print("Total events: " + str(len(misp.events())))
    # today = date.today() - timedelta(days=days_from_today)
    # events = misp.search(object_name="security_event_object",
    #                      pythonify=False,
    #                      date_from=today,
    #                      with_attachments=False)
    # print("Today's events: " + str(len(events)))
    # for event in events:
    #     attack_type_id = -1
    #     pcap_file_id = -1
    #     for attribute in event['Event']['Object'][0]['Attribute']:
    #         if attribute['object_relation'] == 'attack_type':
    #             attack_type_id = attribute['id']
    #         elif attribute['object_relation'] == 'pcap_file':
    #             pcap_file_id = attribute['id']
    #     pcap_file = misp.get_attribute(pcap_file_id, pythonify=True)
    #     open(pcap_path, "wb").write(pcap_file.data.getbuffer())
    #     attacks = [{'attack_type': 'DDoS', 'confidence': '0.99999999'},
    #                {'attack_type': 'malware', 'confidence': '0.15232342345'}]  # TODO call netgen
    #     attack_type_attribute = misp.get_attribute(attack_type_id, pythonify=False)
    #     json_value = json.loads(attack_type_attribute['Attribute']['value'])
    #     json_value['netgen'] = {'version': '0.1', 'attacks': attacks}
    #     attack_type_attribute['Attribute']['value'] = json.dumps(json_value)
    #     attack_type_attribute['Attribute']['timestamp'] = str(datetime.now().timestamp())
    #     misp.update_attribute(attack_type_attribute)
    #     break

    #logger.debug("Event sent to central MISP instance: " + str(event))

if __name__ == "__main__":
    pass
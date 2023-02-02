import json
from typing import Tuple
from pymisp import PyMISP
from pymisp import MISPEvent, MISPAttribute, MISPObject
from pymisp.tools import GenericObjectGenerator
from pymisp.tools import stix
from uuid import uuid4
from datetime import datetime, time, date, timedelta

from helpers.logging_helper import get_logger

logger = get_logger('misp')

# import requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

misp_url = "https://10.101.41.42:8081"
misp_key = "zfajFlj9sOQOZpL7jDFHunSEKU26r8LrxSeaFheY"

misp_verifycert = False
#days_from_today = 100

#https://pymisp.readthedocs.io/en/latest/tools.html#module-pymisp.tools.stix

def publish_on_misp(report = None):

    misp = PyMISP(misp_url, misp_key, misp_verifycert)

    # event = MISPEvent()
    # event.info = 'Dummy event2'

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

    #event = misp.add_event(event, pythonify=True)
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
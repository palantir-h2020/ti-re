import json
from typing import Tuple

# from pymisp import PyMISP
from datetime import datetime, time, date, timedelta

from helpers.logging_helper import get_logger

logger = get_logger('misp')


# # import requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# # test VM
# misp_url = "https://160.97.82.13:4200/"
# misp_key = "3pKX2np7nFLUplxudo2bEcaoFPpNsF5dz7nUexj7"
# # production VM
# # misp_url = "https://150.145.63.141:443/"
# # misp_key = "odCrizmXvTidpn3aUbigFnD04c5wvf7kpBOu9v5q"

# misp_verifycert = False
# days_from_today = 100

# pcap_path = "anomaly.pcap"


# def main():
#     misp = PyMISP(misp_url, misp_key, misp_verifycert)
#     print("Total events: " + str(len(misp.events())))
#     today = date.today() - timedelta(days=days_from_today)
#     events = misp.search(object_name="security_event_object",
#                          pythonify=False,
#                          date_from=today,
#                          with_attachments=False)
#     print("Today's events: " + str(len(events)))
#     for event in events:
#         attack_type_id = -1
#         pcap_file_id = -1
#         for attribute in event['Event']['Object'][0]['Attribute']:
#             if attribute['object_relation'] == 'attack_type':
#                 attack_type_id = attribute['id']
#             elif attribute['object_relation'] == 'pcap_file':
#                 pcap_file_id = attribute['id']
#         pcap_file = misp.get_attribute(pcap_file_id, pythonify=True)
#         open(pcap_path, "wb").write(pcap_file.data.getbuffer())
#         attacks = [{'attack_type': 'DDoS', 'confidence': '0.99999999'},
#                    {'attack_type': 'malware', 'confidence': '0.15232342345'}]  # TODO call netgen
#         attack_type_attribute = misp.get_attribute(attack_type_id, pythonify=False)
#         json_value = json.loads(attack_type_attribute['Attribute']['value'])
#         json_value['netgen'] = {'version': '0.1', 'attacks': attacks}
#         attack_type_attribute['Attribute']['value'] = json.dumps(json_value)
#         attack_type_attribute['Attribute']['timestamp'] = str(datetime.now().timestamp())
#         misp.update_attribute(attack_type_attribute)
#         break

def send_event(event):
    logger.debug("Event sent to central MISP instance: " + event)


if __name__ == "__main__":
    pass
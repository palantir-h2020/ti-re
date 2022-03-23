import json
import logging
import os
import sys

import yaml
from yaml.loader import SafeLoader
import requests


logger = logging.getLogger("rr-tool-helper")
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


def flush_filtering_rules():
    with open('pod.yaml') as f:
        data = yaml.load(f, Loader=SafeLoader)
        for var in data['spec']['containers'][0]['env']:
            if var['name'] == "SC_ORCHESTRATOR_IP":
                SC_ORCHESTRATOR_IP = var['value']
            if var['name'] == "SC_CLUSTER_PORT":
                SC_CLUSTER_PORT = var['value']
            if var['name'] == "IPTABLES_SC_ID":
                IPTABLES_SC_ID = var['value']
            if var['name'] == "ENABLE_MANO_API":
                ENABLE_MANO_API = var['value']

    logger.info("Calling MANO API")
    logger.info("MANO API: resetting filtering rules")
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    url = 'http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns/action?id=' + IPTABLES_SC_ID
    payload = {"action_name": "run", "action_params": {"cmd": "iptables-save | grep -v RR-TOOL_GENERATED | "
                                                              "iptables-restore"}}

    if ENABLE_MANO_API == "1":
        r = requests.post(url, headers=headers, json=payload)

        logger.info("MANO API: response code from orchestrator " + str(r.status_code))
        if r.ok:
            logger.info("MANO API: rules flushed")
        else:
            logger.info("MANO API: failed flushing rules")
            logger.info("MANO API: response headers from orchestrator " + str(r.headers))
            logger.info("MANO API: response text from orchestrator " + str(r.text))
    else:
        logger.info("MANO API: disabled, logger request data")
        logger.info("MANO API: request headers: " + str(headers))
        logger.info("MANO API: request url: " + str(url))
        logger.info("MANO API: request payload: " + str(payload))


# def inject_netflow_alerts():
#     # with open('../pod.yaml') as f:
#     #     data = yaml.load(f, Loader=SafeLoader)
#     #     for var in data['spec']['containers'][0]['env']:
#     #         if var['name'] == "KAFKA_IP":
#     #             KAFKA_IP = var['value']
#     #         if var['name'] == "KAFKA_PORT":
#     #             KAFKA_PORT = var['value']
#     #         if var['name'] == "TOPIC_TI_NETFLOW":
#     #             TOPIC_TI_NETFLOW = var['value']
#     # KAFKA_PRODUCER_PROPERTIES = {
#     #     "bootstrap.servers": KAFKA_IP + ":" + KAFKA_PORT,
#     #     "compression.type": "none"
#     # }
#     import settings
#     folderName = "scripts/netflow_alerts"
#     onlyfiles = [f for f in os.listdir(folderName) if os.path.isfile(os.path.join(folderName, f))]
#     for f in onlyfiles:
#         logger.info("Reading alert file " + folderName + os.sep + f)
#         with open(folderName + os.sep + f, "r", encoding='utf8') as alertFile:
#             alert = json.load(alertFile)
#             producer.Producer(KAFKA_PRODUCER_PROPERTIES).produce(TOPIC_TI_NETFLOW,
#                                                                  json.dumps(alert),
#                                                                  callback=delivery_report,
#                                                                  logger=logger)


def delivery_report(err, msg):
    if err is not None:
        logger.error('message delivery failed with error {}'.format(err))
    else:
        logger.info('message delivered to {} [{}]'.format(msg.topic(), msg.partition()))

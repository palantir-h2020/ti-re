import logging
import yaml
from yaml.loader import SafeLoader
import requests


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

    logging.info("Calling MANO API")
    logging.info("MANO API: resetting filtering rules")
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    url = 'http://' + SC_ORCHESTRATOR_IP + ':' + SC_CLUSTER_PORT + '/lcm/ns/action?id=' + IPTABLES_SC_ID
    payload = {"action_name": "run", "action_params": {"cmd": "iptables-save | grep -v RR-TOOL_GENERATED | "
                                                              "iptables-restore"}}

    if ENABLE_MANO_API == "1":
        r = requests.post(url, headers=headers, json=payload)

        logging.info("MANO API: response code from orchestrator " + str(r.status_code))
        if r.ok:
            logging.info("MANO API: rules flushed")
        else:
            logging.info("MANO API: failed flushing rules")
            logging.info("MANO API: response headers from orchestrator " + str(r.headers))
            logging.info("MANO API: response text from orchestrator " + str(r.text))
    else:
        logging.info("MANO API: disabled, logging request data")
        logging.info("MANO API: request headers: " + str(headers))
        logging.info("MANO API: request url: " + str(url))
        logging.info("MANO API: request payload: " + str(payload))

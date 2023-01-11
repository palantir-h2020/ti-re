import os
from pathlib import Path

from helpers.logging_helper import get_logger

logger = get_logger('settings')

TOOL_DIR = Path(__file__).resolve().parent.parent

if os.getenv('YAML_MANUAL_LOADING') == "1":
    import yaml
    from yaml.loader import SafeLoader

    with TOOL_DIR.joinpath('pod.yaml').open() as f:
        data = yaml.load(f, Loader=SafeLoader)
        for var in data['spec']['containers'][0]['env']:
            if var['name'] not in os.environ.keys():
                os.environ[var['name']] = var['value']
        os.environ['ENABLE_MANO_API'] = "0"
        os.environ['RR_TOOL_MODE'] = "standalone"

system_keys = list(locals().keys())
system_keys.append("system_keys")

# INSTANCE ID
RR_INSTANCE_ID = (os.environ['RR_INSTANCE_IDENTIFIER'])


# KAFKA CONFIGURATION
KAFKA_PRODUCER_PROPERTIES = {
    "bootstrap.servers": (os.environ['KAFKA_IP']) + ":" + (os.environ['KAFKA_PORT']),
    "compression.type": "none"
}

KAFKA_CONSUMER_PROPERTIES = {
    "bootstrap.servers": (os.environ['KAFKA_IP']) + ":" + (os.environ['KAFKA_PORT']),
    "group.id": "test-consumer-group",
    # "auto.offset.reset": "earliest"
}
KAFKA_POLLING_TIMEOUT = float(os.environ['KAFKA_POLLING_TIMEOUT'])

TOPIC_TI_NETFLOW = (os.environ['TOPIC_TI_NETFLOW'])
TOPIC_TI_SYSLOG = (os.environ['TOPIC_TI_SYSLOG'])
TOPIC_RR_PROACTIVE_REMEDIATION = (os.environ['TOPIC_RR_PROACTIVE_REMEDIATION'])
TOPIC_RR_NEW_ATTACK_REMEDIATION = (os.environ['TOPIC_RR_NEW_ATTACK_REMEDIATION'])
TOPIC_PORTAL_NOTIFICATIONS = (os.environ['TOPIC_PORTAL_NOTIFICATIONS'])
TOPIC_IR_INCIDENT_DETECTED = (os.environ['TOPIC_IR_INCIDENT_DETECTED'])
# SC CONFIGURATION

RR_TOOL_MODE = (os.environ['RR_TOOL_MODE'])
ENABLE_ONLY_SECURITY_CAPABILITIES_WITH_TRANSLATOR = (os.environ['ENABLE_ONLY_SECURITY_CAPABILITIES_WITH_TRANSLATOR'])
RESET_SECURITY_CONTROLS_RULES_AT_STARTUP = (os.environ['RESET_SECURITY_CONTROLS_RULES_AT_STARTUP'])
RR_TOOL_IP = (os.environ['RR_TOOL_IP'])
BACKUP_SERVER_IP = (os.environ['BACKUP_SERVER_IP'])
SC_ORCHESTRATOR_IP = (os.environ['SC_ORCHESTRATOR_IP'])
SC_CLUSTER_PORT = (os.environ['SC_CLUSTER_PORT'])
ENABLE_MANO_API = (os.environ['ENABLE_MANO_API'])
ENABLE_IDENTICAL_L4_FILTERING_RULE_SKIPPING = (os.environ['ENABLE_IDENTICAL_L4_FILTERING_RULE_SKIPPING'])
ENABLE_DEFAULT_L4_FILTERING_RULE_PROTOCOL = (os.environ['ENABLE_DEFAULT_L4_FILTERING_RULE_PROTOCOL'])
if ENABLE_DEFAULT_L4_FILTERING_RULE_PROTOCOL == "1":
    ENABLE_DEFAULT_L4_FILTERING_RULE_ATTACKER_PORT = (os.environ['ENABLE_DEFAULT_L4_FILTERING_RULE_ATTACKER_PORT'])
    ENABLE_DEFAULT_L4_FILTERING_RULE_VICTIM_PORT = (os.environ['ENABLE_DEFAULT_L4_FILTERING_RULE_VICTIM_PORT'])
else:
    # if protocol in default L4 filtering rules disabled, ignore attacker/victim port settings
    ENABLE_DEFAULT_L4_FILTERING_RULE_ATTACKER_PORT = "0"
    ENABLE_DEFAULT_L4_FILTERING_RULE_VICTIM_PORT = "0"

ENABLE_DEFAULT_L4_FILTERING_RULE_VICTIM_IP = (os.environ['ENABLE_DEFAULT_L4_FILTERING_RULE_VICTIM_IP'])

TI_SYSLOG_VICTIM_IP_FIELD_NAME = (os.environ['TI_SYSLOG_VICTIM_IP_FIELD_NAME'])

IGRAPH_PICTURES_OUTPUT_FOLDER = str(os.environ['IGRAPH_PICTURES_OUTPUT_FOLDER']).replace('"', '')

logger.info("Settings loaded")


def dump_env_var():
    declared_keys = list(globals().keys())
    for env_var in declared_keys:
        if env_var not in system_keys:
            logger.debug(env_var + ":" + str(globals()[env_var]))
    pass


dump_env_var()

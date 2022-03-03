import os

# KAFKA CONFIGURATION
KAFKA_PRODUCER_PROPERTIES = {
        "bootstrap.servers": (os.environ['KAFKA_IP'])+":"+(os.environ['KAFKA_PORT']),
        "compression.type": "none"
    }

KAFKA_CONSUMER_PROPERTIES = {
        "bootstrap.servers": (os.environ['KAFKA_IP'])+":"+(os.environ['KAFKA_PORT']),
        "group.id": "test-consumer-group",
        #"auto.offset.reset": "earliest"
    }

TOPIC_TI_NETFLOW = (os.environ['TOPIC_TI_NETFLOW'])
TOPIC_TI_SYSLOG = (os.environ['TOPIC_TI_SYSLOG'])
TOPIC_PORTAL_NOTIFICATIONS = (os.environ['TOPIC_PORTAL_NOTIFICATIONS'])
TOPIC_IR_INCIDENT_DETECTED = (os.environ['TOPIC_IR_INCIDENT_DETECTED'])
# SC CONFIGURATION

RR_TOOL_IP = (os.environ['RR_TOOL_IP'])
SC_ORCHESTRATOR_IP = (os.environ['SC_ORCHESTRATOR_IP'])
SC_CLUSTER_PORT = (os.environ['SC_CLUSTER_PORT'])
IPTABLES_SC_ID = (os.environ['IPTABLES_SC_ID'])

TI_SYSLOG_VICTIM_IP_FIELD_NAME = (os.environ['TI_SYSLOG_VICTIM_IP_FIELD_NAME'])

IGRAPH_PICTURES_OUTPUT_FOLDER = (os.environ['IGRAPH_PICTURES_OUTPUT_FOLDER'])

# KAFKA CONFIGURATION

KAFKA_PRODUCER_PROPERTIES = {
        "bootstrap.servers": "10.0.100.3:9092",
        "compression.type": "none"
    }

KAFKA_CONSUMER_PROPERTIES = {
        "bootstrap.servers": "10.0.100.3:9092",
        "group.id": "test-consumer-group",
        #"auto.offset.reset": "earliest"
    }

TOPIC_TI_NETFLOW = 'ti.threat_findings_netflow'
TOPIC_TI_SYSLOG = 'ti.threat_findings_syslog'
TOPIC_PORTAL_NOTIFICATIONS = 'actions-notifications'
TOPIC_IR_INCIDENT_DETECTED = 'ir.detected_incident'
# SC CONFIGURATION

RR_TOOL_IP = '10.?.?.?'
SC_ORCHESTRATOR_IP = '10.101.41.168'
SC_CLUSTER_PORT = '50101'
IPTABLES_SC_ID = 'dfbba196-c6b9-406c-9853-6eabfd865794'

IGRAPH_PICTURES_OUTPUT_FOLDER = ""
import json

from settings import *

from helpers.logging_helper import get_logger
from connectors import message_producer

logger = get_logger('IR_API')


def notify(detected_incident: str, incident_location: str, incident_description: str):
    notification_content = {
        "detectedIncident": detected_incident,
        "incidentLocation": incident_location,
        "incidentDescription": incident_description
    }
    logger.info(f"Incident response API: calling incident response to mitigate following incident: {detected_incident}")
    message_producer.produce(TOPIC_IR_INCIDENT_DETECTED, json.dumps(notification_content), callback=None)

def notify_ransomware(detected_incident: str, incident_location: str, incident_description: str, agent_id: str):
    notification_content = {
        "detectedIncident": detected_incident,
        "incidentLocation": incident_location,
        "incidentDescription": incident_description,
        "nodeId": agent_id
    }
    logger.info(f"Incident response API: calling incident response to mitigate following incident: {detected_incident}")
    message_producer.produce(TOPIC_IR_INCIDENT_DETECTED, json.dumps(notification_content), callback=None)
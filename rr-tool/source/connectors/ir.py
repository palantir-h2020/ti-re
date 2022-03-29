import json

from settings import *

from helpers.logging_helper import get_logger
from connectors.message_producer import MessageProducer

logger = get_logger('IR_API')
message_producer = MessageProducer(KAFKA_PRODUCER_PROPERTIES)


def notify(detected_incident: str, incident_location: str, incident_description: str):
    notification_content = {
        "detectedIncident": detected_incident,
        "incidentLocation": incident_location,
        "incidentDescription": incident_description
    }
    message_producer.produce(TOPIC_IR_INCIDENT_DETECTED, json.dumps(notification_content), callback=None)

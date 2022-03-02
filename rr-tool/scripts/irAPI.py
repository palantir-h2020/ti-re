import json
import logging
from settings import *

from confluent_kafka import Producer

kafka_producer = Producer(KAFKA_PRODUCER_PROPERTIES)

def notify_ir(detectedIncident: str, incidentLocation: str, incidentDescription: str):
    notification_content = {
        "detectedIncident": detectedIncident,
        "incidentLocation": incidentLocation,
        "incidentDescription": incidentDescription
    }
    kafka_producer.produce(TOPIC_IR_INCIDENT_DETECTED, json.dumps(notification_content), callback=delivery_report)

def delivery_report(err, msg):
    if err is not None:
        logging.error('Incident response API: message delivery failed with error {}'.format(err))
    else:
        logging.info('Incident response API: message delivered to {} [{}]'.format(msg.topic(), msg.partition()))
import json

from settings import *

from helpers.logging_helper import get_logger
logger = get_logger('IR_API')

try:
    # noinspection PyUnresolvedReferences
    from confluent_kafka import Producer
    logger.info("Using Kafka message producer")
except ImportError:
    from connectors.message_producer import MessageProducer
    logger.info("Using mockup message producer")

kafka_producer = MessageProducer(KAFKA_PRODUCER_PROPERTIES)


def notify(detected_incident: str, incident_location: str, incident_description: str):
    notification_content = {
        "detectedIncident": detected_incident,
        "incidentLocation": incident_location,
        "incidentDescription": incident_description
    }
    kafka_producer.produce(TOPIC_IR_INCIDENT_DETECTED, json.dumps(notification_content), callback=delivery_report)


def delivery_report(err, msg):
    if err is not None:
        logger.error('Incident response API: message delivery failed with error {}'.format(err))
    else:
        logger.info('Incident response API: message delivered to {} [{}]'.format(msg.topic(), msg.partition()))

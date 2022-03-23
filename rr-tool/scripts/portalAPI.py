import json
import logging
from settings import *

try:
    # noinspection PyUnresolvedReferences
    from confluent_kafka import Producer
except ImportError:
    from producer import Producer

kafka_producer = Producer(KAFKA_PRODUCER_PROPERTIES)

def notify_portal(componentType: str, componentId: str, actionName: str, actionDescription: str, onips: [str]):
    notification_content = {
        "componentType": componentType,
        "componentId": componentId,
        "componentIP": RR_TOOL_IP,
        "actionName": actionName,
        "actionDescription": actionDescription,
        "onIps": onips
    }
    kafka_producer.produce(TOPIC_PORTAL_NOTIFICATIONS, json.dumps(notification_content), callback=delivery_report)


def delivery_report(err, msg):
    if err is not None:
        logging.error('Portal notification API: message delivery failed with error {}'.format(err))
    else:
        logging.info('Portal notification API: message delivered to {} [{}]'.format(msg.topic(), msg.partition()))

import json
import logging
from settings import *

from helpers.logging_helper import get_logger
logger = get_logger('Portal_API')

try:
    # noinspection PyUnresolvedReferences
    from confluent_kafka import Producer
except ImportError:
    from .message_producer import MessageProducer

message_producer = MessageProducer(KAFKA_PRODUCER_PROPERTIES)


def notify(component_type: str, component_id: str, action_name: str, action_description: str, on_ips: [str]):
    notification_content = {
        "componentType": component_type,
        "componentId": component_id,
        "componentIP": RR_TOOL_IP,
        "actionName": action_name,
        "actionDescription": action_description,
        "onIps": on_ips
    }
    message_producer.produce(TOPIC_PORTAL_NOTIFICATIONS, json.dumps(notification_content), callback=delivery_report)


def delivery_report(err, msg):
    if err is not None:
        logging.error('Portal notification API: message delivery failed with error {}'.format(err))
    else:
        logging.info('Portal notification API: message delivered to {} [{}]'.format(msg.topic(), msg.partition()))

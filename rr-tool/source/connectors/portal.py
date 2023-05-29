import json
from settings import *

from helpers.logging_helper import get_logger
from connectors import message_producer

logger = get_logger('Portal_API')


def notify(component_type: str, component_id: str, action_name: str, action_description: str, on_ips: [str]):
    notification_content = {
        "componentType": component_type,
        "componentId": component_id,
        "componentIP": RR_TOOL_IP,
        "actionName": action_name,
        "actionDescription": action_description,
        "onIps": on_ips
    }
    message_producer.produce(TOPIC_PORTAL_NOTIFICATIONS, json.dumps(notification_content), callback=None, sm=False)

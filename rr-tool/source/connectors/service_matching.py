import json

from settings import *

from helpers.logging_helper import get_logger
from connectors import message_producer

from confluent_kafka import Consumer


logger = get_logger('IR_API')


def find_best_secap(nature):
    """ Obtain the list of all the SC subscribed by the user -> LISTSC_FEAT command field
    """
    message = {
        "test": "test",
        "test2": "test"
    }

    message_producer.produce("topiccc", json.dumps(message), callback=None)

    consumer_topic = "test"

    kafka_consumer = Consumer(KAFKA_CONSUMER_PROPERTIES)
    kafka_consumer.subscribe([consumer_topic])

    # Send a message to the endpoint on a certain topic
    kafka_consumer.subscribe([consumer_topic])
    message = kafka_consumer.poll(timeout=100.0)

    # check if a message was received
    if message is not None:
        # process the message
        print(f'Received message: key={message.key()}, value={message.value()}')
    else:
        # handle the timeout condition
        raise Exception('Timeout waiting for message')

    # Close the consumer
    kafka_consumer.close()

    secap_name = message.get("secap_name")
    secap_package_id = message.get("secap_package_id")

    return secap_name

def deploy_secap(secap_package_id, deplyoment_node):
    pass

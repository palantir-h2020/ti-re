import json

from settings import *

from helpers.logging_helper import get_logger
from connectors import message_producer

from confluent_kafka import Consumer


logger = get_logger('IR_API')


def deploy_secap(capabilities, nature, vim_id):
    """ Returns the ID of the security capability deployed """

    consumer_topic = "test"
    producer_topic = "test"

    message = {
        "capabilities": capabilities,
        "nature": nature,
        "vim_id": vim_id
    }

    # Send a message to the endpoint on a certain topic
    message_producer.produce(producer_topic, json.dumps(message), callback=None)

    kafka_consumer = Consumer(KAFKA_CONSUMER_PROPERTIES)
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

    secap_id = message["secap_id"]

    return secap_id

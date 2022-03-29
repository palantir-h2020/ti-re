from settings import *

from helpers.logging_helper import get_logger
logger = get_logger('message_producer')


def default_delivery_report(err, msg):
    if err is not None:
        logger.error('notification delivery failed with error {}'.format(err))
    else:
        logger.info('notification delivered to {} [{}]'.format(msg.topic(), msg.partition()))


class MessageProducer:

    def __init__(self, properties=None) -> None:
        self.properties = properties
        try:
            # noinspection PyUnresolvedReferences
            from confluent_kafka import Producer
            self.kafka_producer = Producer(self.properties)
            self.ENABLE_MOCKUP_PRODUCER = 0
            logger.info("using Kafka message producer")
        except ImportError:
            self.ENABLE_MOCKUP_PRODUCER = 1
            logger.info("using mockup message producer")

    def produce(self, topic, content, callback):
        if self.ENABLE_MOCKUP_PRODUCER == 0:
            if callback is not None:
                self.kafka_producer.produce(topic, content, callback=callback)
            else:
                self.kafka_producer.produce(topic, content, callback=default_delivery_report)
        else:
            logger.info("producing mockup message to topic " + topic + "with content: " + content)


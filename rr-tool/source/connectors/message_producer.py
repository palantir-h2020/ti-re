from settings import *

from helpers.logging_helper import get_logger
logger = get_logger('message_producer')


class MessageProducer:

    def __init__(self, properties=None) -> None:
        self.properties = properties
        try:
            # noinspection PyUnresolvedReferences
            from confluent_kafka import Producer
            self.kafka_producer = Producer(self.properties)
            self.ENABLE_MOCKUP_PRODUCER = 0
        except ImportError:
            self.ENABLE_MOCKUP_PRODUCER = 1

    def produce(self, topic, content, callback):
        if self.ENABLE_MOCKUP_PRODUCER == 0:
            self.kafka_producer.produce(topic, content, callback=callback)
            if logger is not None:
                logger.info("Message sent")
        else:
            logger.info("Mockup Kafka producer: producing message to topic " + topic)
            logger.info("Mockup Kafka producer: " + content)
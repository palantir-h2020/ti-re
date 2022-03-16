import logging


class Producer:

    def __init__(self, properties=None) -> None:
        self.properties = properties

    @staticmethod
    def produce(topic, content, callback):
        logging.info("Mockup Kafka producer: producing message to topic " + topic)
        logging.info("Mockup Kafka producer: " + content)

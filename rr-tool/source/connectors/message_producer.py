from settings import *

from helpers.logging_helper import get_logger
logger = get_logger('message_producer')

try:
    # noinspection PyUnresolvedReferences
    from confluent_kafka import Producer

    kafka_producer = Producer(KAFKA_PRODUCER_PROPERTIES)
    ENABLE_MOCKUP_PRODUCER = 0
    logger.info("using Kafka message producer")
except ImportError:
    ENABLE_MOCKUP_PRODUCER = 1
    logger.info("using mockup message producer")

#TODO @Francesco: check parametro sm mancante
def produce(topic, content, callback, sm = False):
    if ENABLE_MOCKUP_PRODUCER == 0:
        if callback is not None:
            kafka_producer.produce(topic, content, callback=callback)
        else:
            kafka_producer.produce(topic, content, callback=default_delivery_report)
        if sm == True:
            kafka_producer.flush()
    else:
        logger.info("producing mockup message to topic " + topic + "with content: " + content)


def default_delivery_report(err, msg):
    if err is not None:
        logger.error('notification delivery failed with error {}'.format(err))
    else:
        logger.info('notification delivered to {} [{}]'.format(msg.topic(), msg.partition()))

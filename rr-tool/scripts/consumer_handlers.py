import simplejson as json

from settings import *
from confluent_kafka import Consumer

remediator_instance = None


def start_kafka_consumer(stop_event, logger, remediator):
    logger.info("Starting Kafka Consumer set up ...")

    global remediator_instance
    remediator_instance = remediator

    kafka_consumer = Consumer(KAFKA_CONSUMER_PROPERTIES)

    kafka_consumer.subscribe([TOPIC_TI_NETFLOW, TOPIC_TI_SYSLOG])

    switch_consumer_handlers = {
        TOPIC_TI_NETFLOW: handle_threat_findings_netflow,
        TOPIC_TI_SYSLOG: handle_threat_findings_syslog
    }

    logger.info("Before while loop ...")

    while not stop_event.is_set():
        msg = kafka_consumer.poll(KAFKA_POLLING_TIMEOUT)

        if msg is None:
            logger.info("No message found!")
            continue
        if msg.error():
            logger.error("Consumer error: {}".format(msg.error()))
            continue
        if msg.topic() is None:
            logger.info("Received message has None topic")
            continue

        logger.info("Message value: %s", msg.value().decode('utf-8'))

        switch_consumer_handlers[msg.topic()](msg.value().decode('utf-8'), logger)

    kafka_consumer.close()


def handle_threat_findings_netflow(msg, logger=None):
    json_msg = json.loads(msg)
    remediator_instance.stringInputNetflow(msg)


def handle_threat_findings_syslog(msg, logger=None):
    json_msg = json.loads(msg)
    remediator_instance.stringInputSyslog(msg)

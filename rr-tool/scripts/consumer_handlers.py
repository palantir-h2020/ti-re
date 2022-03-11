# noinspection PyUnresolvedReferences
from confluent_kafka import Consumer

from remediation import Remediator
from settings import *

remediator_instance: Remediator = None

receivedMessageCounters = {}

def start_kafka_consumer(stop_event, logger, remediator: Remediator):
    logger.info("Kafka consumer: starting setup")

    global remediator_instance
    remediator_instance = remediator

    kafka_consumer = Consumer(KAFKA_CONSUMER_PROPERTIES)

    kafka_consumer.subscribe([TOPIC_TI_NETFLOW, TOPIC_TI_SYSLOG])

    switch_consumer_handlers = {
        TOPIC_TI_NETFLOW: handle_threat_findings_netflow,
        TOPIC_TI_SYSLOG: handle_threat_findings_syslog
    }

    for topic in switch_consumer_handlers.keys():
        receivedMessageCounters[topic] = 0

    logger.info("Kafka consumer: started polling on Kafka Broker " + (os.environ['KAFKA_IP']) + ":" + (
        os.environ['KAFKA_PORT']))

    while not stop_event.is_set():
        msg = kafka_consumer.poll(KAFKA_POLLING_TIMEOUT)

        if msg is None:
            # logger.info("No message found!")
            continue
        if msg.error():
            logger.error("Kafka consumer: consumer error: {}".format(msg.error()))
            continue
        if msg.topic() is None:
            logger.info("Kafka consumer: received message has None topic")
            continue

        logger.info("Kafka consumer: received message: %s", msg.value().decode('utf-8'))

        receivedMessageCounters[msg.topic()] += 1
        for topic in switch_consumer_handlers.keys():
            logger.info("Kafka consumer: messages received on topic "+topic+": "+str(receivedMessageCounters[topic]))
        switch_consumer_handlers[msg.topic()](msg.value().decode('utf-8'), logger)

    kafka_consumer.close()


def handle_threat_findings_netflow(msg, logger=None):
    # json_msg = json.loads(msg)
    remediator_instance.stringInputNetflow(msg)


def handle_threat_findings_syslog(msg, logger=None):
    # json_msg = json.loads(msg)
    remediator_instance.stringInputSyslog(msg)

import threading

# noinspection PyUnresolvedReferences
from confluent_kafka import Consumer

from settings import *

from helpers.logging_helper import get_logger

logger = get_logger('Kafka_consumer')


# TODO check in testbed if the logger should be passed as a parameter to start_kafka_consumer or current global is ok

def consume_topics(remediator):
    # KAFKA Consumer set up
    kafka_consumer_stop_event = threading.Event()
    kafka_consumer_thread = threading.Thread(target=start_kafka_consumer,
                                             args=[kafka_consumer_stop_event, remediator])
    kafka_consumer_thread.start()


def start_kafka_consumer(stop_event, remediator):
    receivedMessageCounters = {}
    receivedDuplicatedMessageCounters = {}
    receivedMessageHashes = {}

    logger.info("setup started")

    kafka_consumer = Consumer(KAFKA_CONSUMER_PROPERTIES)

    kafka_consumer.subscribe([TOPIC_TI_NETFLOW, TOPIC_TI_SYSLOG, TOPIC_RR_PROACTIVE_REMEDIATION, TOPIC_RR_NEW_ATTACK_REMEDIATION])

    switch_consumer_handlers = {
        TOPIC_TI_NETFLOW: remediator.stringInputNetflow,
        TOPIC_TI_SYSLOG: remediator.stringInputSyslog,
        TOPIC_RR_PROACTIVE_REMEDIATION: remediator.performProactiveRemediation,
        TOPIC_RR_NEW_ATTACK_REMEDIATION: remediator.addNewAttackRemediation
    }

    topic_list = []

    for topic in switch_consumer_handlers.keys():
        receivedMessageCounters[topic] = 0
        receivedDuplicatedMessageCounters[topic] = 0
        receivedMessageHashes[topic] = []
        topic_list.append(topic)

    logger.info("started polling on Kafka Broker " + (os.environ['KAFKA_IP']) + ":" + (
        os.environ['KAFKA_PORT']) + " for topics " + str(topic_list))

    i = 0
    while not stop_event.is_set():
        msg = kafka_consumer.poll(KAFKA_POLLING_TIMEOUT)

        if msg is None:
            # logger.info("No message found!")
            if i < 3:
                print(".", end='', flush=True)
                i += 1
            else:
                i = 0
                print("\r   ", end='\r', flush=True)
            continue
        if msg.error():
            i = 0
            print()
            logger.error("error: {}".format(msg.error()))
            continue
        if msg.topic() is None:
            i = 0
            print()
            logger.error("received message has None topic")
            continue

        i = 0
        print()
        logger.info("received message on topic %s: %s", msg.topic(), msg.value().decode('utf-8'))
        receivedMessageCounters[msg.topic()] += 1

        msgHash = hash(msg.value())
        duplicated = False
        if msgHash in receivedMessageHashes[msg.topic()]:
            duplicated = True
            logger.info("duplicated message received on topic " + msg.topic())
            receivedDuplicatedMessageCounters[msg.topic()] += 1
        else:
            receivedMessageHashes[msg.topic()].append(msgHash)

        if not duplicated:
            switch_consumer_handlers[msg.topic()](msg.value().decode('utf-8'), logger)

        for topic in switch_consumer_handlers.keys():
            logger.info("messages received on topic " + topic + ": "
                        + str(receivedMessageCounters[topic]) + "("
                        + str(receivedDuplicatedMessageCounters[topic]) + ")")

        logger.info("waiting for new messages from Kafka Broker " + (os.environ['KAFKA_IP']) + ":" + (
            os.environ['KAFKA_PORT']) + " for topics " + str(topic_list))
    kafka_consumer.close()

# def handle_threat_findings_netflow(msg, logger=None):
#     # json_msg = json.loads(msg)
#     try:
#         remediator_instance.stringInputNetflow(msg)
#     except Exception as e:
#         logger.error("Kafka consumer: alert ignored, remediator exception: "+str(e))
#
#
# def handle_threat_findings_syslog(msg, logger=None):
#     # json_msg = json.loads(msg)
#     try:
#         remediator_instance.stringInputSyslog(msg)
#     except Exception as e:
#         logger.error("Kafka consumer: alert ignored, remediator exception: "+str(e))

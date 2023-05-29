from settings import *
from confluent_kafka import AdminClient
from helpers.logging_helper import get_logger

logger = get_logger('BROADCAST_MESSAGE_PRODUCER')

# a kafka message producer that writes on all partitions of a given topic

try:
    # noinspection PyUnresolvedReferences
    from confluent_kafka import Producer

    kafka_producer = Producer(KAFKA_PRODUCER_PROPERTIES)
    ENABLE_MOCKUP_PRODUCER = 0

    logger.info("using Kafka message producer")
except ImportError:
    ENABLE_MOCKUP_PRODUCER = 1
    logger.info("using mockup message producer")


def broadcast_message(topic, content, callback):
    # Create the admin client
    admin_client = AdminClient(KAFKA_ADMIN_CLIENT_CONFIG)

    # Retrieve metadata for the topic
    metadata = admin_client.list_topics(topic=topic)

    # Check if the topic exists in the metadata
    if topic in metadata.topics:
        # Retrieve the partition information for the topic
        partitions = metadata.topics[topic].partitions
        partition_count = len(partitions)

        # Print the number of partitions
        logger.info(f"Number of partitions for topic '{topic}': {partition_count}")

        # Print the list of partitions
        partition_list = [partition.partition_id for partition in partitions]
        logger.info(f"List of partitions for topic '{topic}': {partition_list}")
    else:
        logger.info(f"Topic '{topic}' does not exist.")

    # Close the admin client
    admin_client.close()

    for partition_id in partition_list:
        message_producer(topic, content, partition_id, callback)


def message_producer(topic, content, partition, callback):
    if ENABLE_MOCKUP_PRODUCER == 0:
        if callback is not None:
            kafka_producer.produce(topic, content, partition=partition, callback=callback)
        else:
            kafka_producer.produce(topic, content, partition=partition, callback=default_delivery_report)
    else:
        logger.info("producing mockup message to topic " + topic + "with content: " + content)



def default_delivery_report(err, msg):
    if err is not None:
        logger.error('notification delivery failed with error {}'.format(err))
    else:
        logger.info('notification delivered to {} [{}]'.format(msg.topic(), msg.partition()))



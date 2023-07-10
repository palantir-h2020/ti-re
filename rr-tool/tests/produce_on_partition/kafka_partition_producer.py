import json
import os
from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient

KAFKA_PRODUCER_PROPERTIES = {
    "bootstrap.servers": "10.101.41.255" + ":" + "9092",
    "compression.type": "none"
}

KAFKA_ADMIN_CLIENT_CONFIG = {
    "bootstrap.servers": "10.101.41.255" + ":" + "9092"
}

kafka_producer = Producer(KAFKA_PRODUCER_PROPERTIES)

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
        print(f"Number of partitions for topic '{topic}': {partition_count}")

        print(partitions)
        partition_list = list(partitions.keys())
        print(f"List of partitions for topic '{topic}': {partition_list}")
    else:
        print(f"Topic '{topic}' does not exist.")

    for partition_id in partition_list:
        message_producer(topic, content, partition_id, callback)
        #message_producer(topic, json.dumps({"test:": partition_id}), partition_id, callback)

def message_producer(topic, content, partition, callback):
    kafka_producer.produce(topic, content, partition=partition, callback=callback)
    kafka_producer.flush()

alert = {
        "Threat_Finding": {
            "Time_Start": "2020-04-29 13:51:46",
            "Time_End": "2021-04-29 13:52:51",
            "Time_Duration": "64",
            "Source_Address": "10.0.2.108",
            "Destination_Address": "87.236.215.56",
            "Source_Port": 61868,
            "Destination_Port": 80,
            "Protocol": "TCP",
            "Flag": "...APRS.",
            "Source_tos": 0,
            "Input_packets": 5,
            "Input_bytes": 1177
        },
        "Threat_Label": "crypto",
        "Threat_Category": "malware",
        "Classification_Confidence": 0.3346123530318716,
        "Outlier_Score": 0.5940769567160774
    }

message_producer("ti.threat_findings_netflow_rrtooldebug", json.dumps(alert), 22, None)

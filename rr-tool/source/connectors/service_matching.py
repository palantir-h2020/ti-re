import json
import random

import settings

from helpers.logging_helper import get_logger
from connectors import message_producer

from confluent_kafka import Consumer


logger = get_logger('SERVICE_MATCHING_CONNECTOR')

request_message_example = {
    "session": "43", # correlation id
    "realm": "orion",
    "action": "SIMULDEPLOY",
    "parameter":[{
        "mechName": "",
        "nature": "network_flow_monitoring",  # level_4_filtering
        "subscriptionId": "",
        "billingPeriod": "1000",
        "imposedInfras": ["3f5eb7fa-a58d-4589-a93b-7ae403716a0f"], # vim id
        "whitelistScs": ["snort2"] # iptables
    }]
}

response_message_example = {
    "session": 43,
    "success": True,
    "error": 0,
    "content": {
        "cost": 20040.0,
        "effectivelyDeployed": True,
        "content":[{
            "scId": "ed55d9c0-12ab-4df7-8695-22e1ac38a18b",
            "billingModel": "HOURLY",
            "sla": 0.0,
            "infrastructureId": "3f5eb7fa-a58d-4589-a93b-7ae403716a0f",
            "deploymentModel": "Cloud",
            "typeCounterMeasure": "network_flow_monitoring_", # detectionMethod_mitigationMethod
            "instanceId": "-1" #
        }]
    }
}

def deploy_secap(requested_capability,
                compatible_security_controls,
                vim_id=settings.VIM_ID):
    """ Deploys a new security control (security capability
        in Palantir vocabulary) in the network landscape
        Args:
            requested_capability (string): the requested security capability
            which the deployed security control must support.

            compatible_security_controls (list of strings): a list of
            security controls for which the RR-tool supports command
            generation. The deployed security control must come from
            this list.

            vim_id (string): this is the ID of the network landascape node
            in which the security control must be deployed.

        Returns:
            string: the ID of the security capability deployed
    """


    correlation_id = random.randint(10, 100000)


# 6 corresponds to iptnetflow

    request_message = {
        "session": correlation_id, # correlation id
        "realm": "orion",
        "action": "DEPLOY", # SIMULDEPLOY
        "parameter":[{
            "mechName": "",
            "nature": "network_flow_monitoring", # requested_capability,  # rr-tool internal: level_4_filtering. sm equivalent:
            "subscriptionId": "",
            "billingPeriod": "1000",
            "imposedInfras": [vim_id], # vim id
            "whitelistScs": compatible_security_controls # iptables compatible secap...
        }]
    }

    # Send a message to the endpoint on a certain topic
    message_producer.produce(settings.TOPIC_SERVICE_MATCHING_REQUESTS,
                            json.dumps(request_message),
                            callback=None)

    # WARNING: this consumer MUST use a different group.id from the one used by the RR-tool
    # main consumer (the one receiving threat alerts), otherwise strange behavior may occur,
    # or itwon't work at all.
    # Check KAFKA_CONSUMER_SM_PROPERTIES in settings
    kafka_consumer = Consumer(settings.KAFKA_CONSUMER_SM_PROPERTIES)
    kafka_consumer.subscribe([settings.TOPIC_SERVICE_MATCHING_RESPONSES])

    response = None

    while response == None:

        logger.info("Waiting for SM response from Kafka broker on topic "
                + settings.TOPIC_SERVICE_MATCHING_REQUESTS)

        message = kafka_consumer.poll(timeout=100.0)

        # check if a message was received
        if message is not None:
            logger.info(f"Received message: key={message.key()}, value={message.value().decode('utf-8')}")

            # serialize message
            message = json.loads(message.value().decode('utf-8'))

            # check response correlation with the request sent on the producer_topic
            if message.get("session") == correlation_id:
                logger.info(f"Received response from SM!")
                if (message.get("success") is True and
                    message.get("content").get("effectivelyDeployed") is True and
                    message.get("content").get("content")[0].get("instanceId") != "-1"):

                    logger.info(f"Successfully deployed new security capability")

                    # is it safe to assume only 1 secap is present in the list, given that only 1 was required in the request ?
                    response = message.get("content").get("content")[0].get("instanceId")
                    break

                else:
                    logger.error(f"An error occurred in the Service Matching: {message.get('error')}")
                    logger.error(f"Unable to deploy new security capability.")
            else:
                logger.info(f"Message not for RR-tool, discard it")



    # Close the consumer
    kafka_consumer.close()

    return response
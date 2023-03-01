import json
import random

import settings

from helpers.logging_helper import get_logger
from connectors import message_producer

from confluent_kafka import Consumer


logger = get_logger('IR_API')

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
        "effectivelyDeployed": False,
        "content":[{
            "scId": "ed55d9c0-12ab-4df7-8695-22e1ac38a18b",
            "billingModel": "HOURLY",
            "sla": 0.0,
            "infrastructureId": "3f5eb7fa-a58d-4589-a93b-7ae403716a0f",
            "deploymentModel": "Cloud",
            "typeCounterMeasure": "network_flow_monitoring_",
            "instanceId": "-1"
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
    correlation_id = random.randint(10, 1000)

    request_message = {
        "session": correlation_id, # correlation id
        "realm": "orion",
        "action": "SIMULDEPLOY",
        "parameter":[{
            "mechName": "",
            "nature": requested_capability,  # rr-tool internal: level_4_filtering. sm:
            "subscriptionId": "",
            "billingPeriod": "1000",
            "imposedInfras": [vim_id], # vim id
            "whitelistScs": compatible_security_controls # iptables compatible secap... iptnetflow?
        }]
    }

    # Send a message to the endpoint on a certain topic
    message_producer.produce(settings.TOPIC_SERVICE_MATCHING_REQUESTS,
                            json.dumps(request_message),
                            callback=None)

    kafka_consumer = Consumer(settings.KAFKA_CONSUMER_PROPERTIES)
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
            if message["session"] == correlation_id:

                if message.get("success") is True:
                    logger.info(f"Successfully deployed new security capability")

                    # is it safe to assume only 1 secap in the list, given that only 1 was required in the request ?
                    response = message.get("content").get("content")[0].get("instanceId")
                    break

                else:
                    logger.info(f"An error occurred in the Service Matching: {message.get('error')}")
                    logger.info(f"Unable to deploy new security capability.")


    # Close the consumer
    kafka_consumer.close()

    return response
import logging
import threading
import json
from consumer_handlers import start_kafka_consumer

from remediation import Remediator


def main():
    with open("SecurityControlRepository.json", "r", encoding='utf8') as SecurityControlRepositoryFile:
        securityControlRepository = json.load(SecurityControlRepositoryFile)["SecurityControls"]
    with open("ThreatRepository.json", "r", encoding='utf8') as ThreatRepositoryFile:
        threatRepository = json.load(ThreatRepositoryFile)["Threats"]

    remediator = Remediator(SecurityControlRepository=securityControlRepository,
                            ThreatRepository=threatRepository)

    # KAFKA Consumer set up
    kafka_consumer_stop_event = threading.Event()
    kafka_consumer_thread = threading.Thread(target=start_kafka_consumer,
                                             args=[kafka_consumer_stop_event, logging.getLogger('thread'), remediator])
    kafka_consumer_thread.start()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.exception(e)

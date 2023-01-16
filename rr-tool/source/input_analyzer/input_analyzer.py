from typing import Dict

import settings
from helpers.logging_helper import get_logger

logger = get_logger('input-analyzer')


def prepareDataForRemediationOfMalware(global_scope, service_graph_instance, threat_repository,
                                       threat_category, threat_label, protocol, impacted_host_port,
                                       impacted_host_ip, attacker_port, attacker_ip):

    global_scope["threat_category"] = threat_category  # botnet
    global_scope["threat_label"] = threat_label  # unknown / Cridex / Zeus
    global_scope["protocol"] = protocol
    global_scope["impacted_host_port"] = impacted_host_port
    global_scope["impacted_host_ip"] = impacted_host_ip  # 10.1.0.10
    global_scope["c2serversPort"] = attacker_port  # 22
    global_scope["attacker_ip"] = attacker_ip  # 12.12.12.12

    # TODO remove this temporary fix after having landscape information/ip changes in alerts
    service_graph_instance.changeNodeIP("victim", impacted_host_ip)
    service_graph_instance.changeNodeIP("attacker", attacker_ip)

    global_scope["rules_level_4"] = []
    global_scope["rules_level_7"] = []

    if threat_label in threat_repository[threat_category]:

        logger.info("Threat found in the repository, adding specific countermeasures ...")

        malware_specific_mitigation_rules = threat_repository[threat_category][threat_label]["rules"]

        global_scope["rules_level_7"] = \
            [rule for rule in malware_specific_mitigation_rules
             if rule.get("level") == 7 and rule.get("proto") != "DNS"]  # DNS rules are managed below

        global_scope["rules_level_4"] = \
            [rule for rule in malware_specific_mitigation_rules
             if rule.get("level") == 4]

        # complete ThreatRepository data with fresh information regarding port and victim host received as alert
        for rule in global_scope["rules_level_4"]:
            rule["victimIP"] = impacted_host_ip
            rule["victimPort"] = impacted_host_port
            rule["c2serversPort"] = attacker_port

        # Block the attacker ip took from the information present in the alert.
        # A new L4 filtering rule is thus created if the attacker ip present in
        # the alert isn't already in the ThreatRepository or if the threat
        # repository doesn't contain specific level_4_filtering rules
        threatRepositoryAttackers = \
            [rule["c2serversIP"] for rule in malware_specific_mitigation_rules if rule.get("level") == 4]
        if attacker_ip not in threatRepositoryAttackers or len(global_scope["rules_level_4"]) == 0:
            setupDefaultL4RemediationRules(global_scope,
                                        protocol,
                                        impacted_host_ip,
                                        impacted_host_port,
                                        attacker_ip,
                                        attacker_port)

        # get dns rules
        global_scope["domains"] = [rule["domain"] for rule in malware_specific_mitigation_rules if
                                   rule.get("proto") == "DNS"]

        # set impacted_nodes variable, that is used in the other recipes
        global_scope["impacted_nodes"] = [impacted_host_ip]

    else:

        logger.info("Threat not found in the repository, applying generic countermeasures ...")
        setupDefaultL4RemediationRules(global_scope,
                                        protocol,
                                        impacted_host_ip,
                                        impacted_host_port,
                                        attacker_ip,
                                        attacker_port)

    # Logging

    logger.debug(f"Impacted host ip: {impacted_host_ip})")

    if impacted_host_port != "":
        logger.debug(f"Impacted host port: {impacted_host_port}")
    logger.debug(f"Attacker ip: {attacker_ip}")

    if attacker_port != "":
        logger.debug(f"Attacker port {attacker_port}")

    if protocol != "":
        logger.debug(f"L4 protocol {protocol}")

    for rule in global_scope["rules_level_7"]:
        payload = rule["payload"]
        logger.info(f"Payload: {payload}")

def setupDefaultL4RemediationRules(global_scope, protocol, impacted_host_ip, impacted_host_port, attacker_ip,
                                   attacker_port) -> Dict:

    # Add a filtering rule for both traffic directions:
    rules = [{"level": 4, "c2serversIP": attacker_ip}, {"level": 4, "victimIP": attacker_ip}]

    if settings.ENABLE_DEFAULT_L4_FILTERING_RULE_VICTIM_IP == '1':
        rules[0]["victimIP"] = impacted_host_ip
        rules[1]["c2serversIP"] = impacted_host_ip

    if settings.ENABLE_DEFAULT_L4_FILTERING_RULE_ATTACKER_PORT == '1':
        rules[0]["c2serversPort"] = attacker_port
        rules[1]["victimPort"] = attacker_port

    if settings.ENABLE_DEFAULT_L4_FILTERING_RULE_VICTIM_PORT == '1':
        rules[0]["victimPort"] = impacted_host_port
        rules[1]["c2serversPort"] = impacted_host_port

    if settings.ENABLE_DEFAULT_L4_FILTERING_RULE_PROTOCOL == '1':
        rules[0]["proto"] = protocol
        rules[1]["proto"] = protocol

    if "rules_level_4" not in global_scope.keys():
        global_scope["rules_level_4"] = rules
    else:
        for rule in rules:
            global_scope["rules_level_4"].append(rule)

def prepareDataForRemediationOfUnauthorizedAccess(global_scope, service_graph_instance, alert) -> Dict:
    # GlobalScope["AnomalyDetectionSyslog"] = alert.get("AnomalyDetectionSyslog")
    # GlobalScope["Threat_Label"] = alert.get("Threat_Label")
    # GlobalScope["Classification_Confidence"] = alert("Classification_Confidence")
    # GlobalScope["Outlier_Score"] = alert("Outlier_Score")
    global_scope["UnauthorizedAccessAlert"] = alert
    global_scope["UnauthorizedAccessAlertSourceIp"] = alert[settings.TI_SYSLOG_VICTIM_IP_FIELD_NAME]
    global_scope["BackupServerIp"] = settings.BACKUP_SERVER_IP

    # TODO remove this temporary fix after having landscape information/ip changes in alerts
    service_graph_instance.changeNodeIP("victim", global_scope["UnauthorizedAccessAlertSourceIp"])

    # Add a filtering rule for both traffic directions:
    global_scope["rules_level_4"] = [
        {"level": 4, "victimIP": global_scope["UnauthorizedAccessAlertSourceIp"],
         "c2serversPort": "", "action": "DENY"},
        {"level": 4, "c2serversIP": global_scope["UnauthorizedAccessAlertSourceIp"],
         "c2serversPort": "", "action": "DENY"},
        {"level": 4, "victimIP": global_scope["UnauthorizedAccessAlertSourceIp"],
         "c2serversPort": "", "c2serversIP": settings.BACKUP_SERVER_IP,
         "proto": "", "action": "ALLOW"},
        {"level": 4, "victimIP": settings.BACKUP_SERVER_IP,
         "c2serversPort": "", "c2serversIP": global_scope["UnauthorizedAccessAlertSourceIp"],
         "proto": "", "action": "ALLOW"}
    ]

def prepareDataForProactiveRemediation(global_scope, threat_repository, threat_category, threat_label, artifacts):

    global_scope["threat_category"] = threat_category  # botnet
    global_scope["threat_label"] = threat_label  # unknown / Cridex / Zeus
    global_scope["attacker_ip"] = artifacts["attacker_ip"]  # 12.12.12.12
    global_scope["attacker_port"] = artifacts["attacker_port"]  # 22

    rules_level_4 = []
    rules_level_7 = []

    if threat_label in threat_repository[threat_category]:

        threat_repository_mitigation_rules = threat_repository[threat_category][threat_label]["rules"]

        rules_level_7 = \
                [rule for rule in threat_repository_mitigation_rules
                if rule.get("level") == 7 and rule.get("proto") != "DNS"]
                # DNS rules are level 7 but are managed with the "domains" artifact

        rules_level_4 = \
                [rule for rule in threat_repository_mitigation_rules
                if rule.get("level") == 4]

    # get dns rules
    global_scope["domains"] = [rule["domain"] for rule in threat_repository_mitigation_rules if
                                rule.get("proto") == "DNS"]

    # Add a filtering rule for both traffic directions:
    rules_level_4.append({"level": 4,
                        "c2serversPort": artifacts["attacker_ip"],
                        "c2serversIP": artifacts["attacker_port"],
                        "proto": "TCP",
                        "action": "DENY"})

    rules_level_4.append({"level": 4,
                        "victimIP": artifacts["attacker_ip"],
                        "victimPort": artifacts["attacker_port"],
                        "proto": "TCP",
                        "action": "DENY"})

    if "payload" in artifacts:

        # Add a filtering rule for both traffic directions:
        rules_level_7.append({"level": 7,
                            "victimIP": artifacts["attacker_ip"],
                            "victimPort": artifacts["attacker_port"],
                            "payload": artifacts["payload"],
                            "proto": "TCP",
                            "action": "DENY"})

        rules_level_7.append({"level": 7,
                            "victimIP": artifacts["attacker_ip"],
                            "victimPort": artifacts["attacker_port"],
                            "payload": artifacts["payload"],
                            "proto": "TCP",
                            "action": "DENY"})

    global_scope["rules_level_4"] = rules_level_4
    global_scope["rules_level_7"] = rules_level_7
from datetime import datetime
import json
import os
import base64
import stix2
from stix2.v21 import (
    TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE,
)
from settings import ENABLE_PRIVATE_ARTIFACTS_SHARING

from helpers.logging_helper import get_logger

logger = get_logger('stix-helper')

# Best practices on whether or not to include extension definitions
# alongside the STIX bundle.
# https://github.com/oasis-open/cti-python-stix2/issues/535


# Declaring custom objects as class
# https://github.com/oasis-open/cti-python-stix2/issues/429

def getSTIXReport(global_scope, threat_type):

    if threat_type == "unauthorized_access":
        results = getSTIXReport_unauthorized_access(global_scope)
    elif threat_type == "botnet":
        results = getSTIXReport_botnet(global_scope)
    elif threat_type == "ransomware":
        results = getSTIXReport_ransomware(global_scope)

    return results

def getSTIXReport_unauthorized_access(global_scope):

    threat_name = global_scope.get("threat_label")
    attacker_ip = global_scope.get("UnauthorizedAccessAlertSourceIp")

    if ENABLE_PRIVATE_ARTIFACTS_SHARING == "1":
        impacted_host_ip = global_scope.get("UnauthorizedAccessAlertSourceIp")
    else:
        impacted_host_ip = "X.X.X.X"

    organization_id = global_scope.get("organization_id")

    mitre_enterprise_attack_file = stix2.MemoryStore()
    mitre_enterprise_attack_file.load_from_file("enterprise-attack.json")

    timestamp_now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    coa_extension_definition_file = stix2.MemoryStore()
    coa_extension_definition_file.load_from_file("stix_coa_extension_definition.json")
    coa_extension_definition = coa_extension_definition_file.get("extension-definition--1e1c1bd7-c527-4215-8e18-e199e74da57c")

    attack_pattern = mitre_enterprise_attack_file.query([
        stix2.Filter("external_references.external_id", "=", "T1134"),
        stix2.Filter("type", "=", "attack-pattern")
    ])[0]

    kill_chain_phases = attack_pattern.kill_chain_phases

    identitySDO = stix2.Identity(name=f"Organization ID.{organization_id}",
                                identity_class="organization")

    # CACAO playbook of the course of action in response to a sigthning of an indicator
    remediationPlaybook = {} # todo

    attackerIpSCO = stix2.v21.IPv4Address(value=attacker_ip)

    impactedHostIpSCO = stix2.v21.IPv4Address(value=impacted_host_ip,
                                                object_marking_refs=[TLP_RED["id"]])

    trafficSCO = stix2.v21.NetworkTraffic(src_ref=impactedHostIpSCO["id"],
                                            dst_ref= attackerIpSCO["id"],
                                            protocols=["tcp"],
                                            dst_port=22)

    #Observed data
    ObservedDataSDO = stix2.v21.ObservedData(object_refs=
                                    [attackerIpSCO["id"],
                                    impactedHostIpSCO["id"],
                                    trafficSCO["id"]],
                                    first_observed = timestamp_now,
                                    last_observed = timestamp_now,
                                    number_observed = 1)

    # Malware
    MalwareSDO = stix2.v21.Malware(name=threat_name,
                                    is_family=False,
                                    kill_chain_phases=kill_chain_phases)

    # Indicator of compromise
    IoCSDO = stix2.v21.Indicator(indicator_types=["malicious-activity"],
                                valid_from=timestamp_now,
                                pattern_type="None",
                                pattern="None",
                                name="Malicious traffic",
                                description="Traffic related to multiple unauthorized login attempts",
                                kill_chain_phases=kill_chain_phases,
                                labels= ["malicious-activity"])

    infraVictim = stix2.v21.Infrastructure(name = "Victim host",
                                        description = "The host being part of the botnet",
                                        infrastructure_types = ["workstation"])

    infraAttacker = stix2.v21.Infrastructure(name = "Attacker host",
                                        description = "The command and control server of the botnet",
                                        infrastructure_types = ["command-and-control", "botnet"])

    # Course of action
    CoASDO = stix2.v21.CourseOfAction(description="CACAO Playbook course of action",
                                    name="CACAO playbook",
                                    extensions={
                                        coa_extension_definition["id"] : {
                                            "extension_type": "property-extension",
                                            # "created": timestamp_now,
                                            # "modified": timestamp_now,
                                            "playbook_standard": "playbook_standard",
                                            "playbook_bin": global_scope["cacao_playbook_base64"],
                                        },
                                    },
                                    created_by_ref=identitySDO["id"])

    # Report
    reportSDO = stix2.v21.Report(name="Unauthorized access remediation",
                            published=timestamp_now,
                            object_refs=[IoCSDO["id"], identitySDO["id"] ]) # CoASDO["id"], ext["id"]

    # # Relationship between course of action and indicator of compromise
    # rel = stix2.v21.Relationship(relationship_type="mitigates", #remediates
    #                                 source_ref=CoASDO["id"],
    #                                 target_ref=IoCSDO["id"],
    #                                 created_by_ref=identitySDO["id"])

    # Relationship between identitySDO and the report
    rel2 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=identitySDO["id"],
                                    target_ref=reportSDO["id"],
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of compromise and malware
    rel3 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of report and malware
    rel4 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=reportSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    rel5 = stix2.v21.Relationship(relationship_type="consists-of",
                                    source_ref=infraVictim["id"],
                                    target_ref=impactedHostIpSCO["id"])

    rel6 = stix2.v21.Relationship(relationship_type="consists-of",
                                    source_ref=infraAttacker["id"],
                                    target_ref=attackerIpSCO["id"])

    rel7 = stix2.v21.Relationship(relationship_type="communicates-with",
                                    source_ref=infraVictim["id"],
                                    target_ref=infraAttacker["id"])

    rel8 = stix2.v21.Relationship(relationship_type="targets",
                                    source_ref=attack_pattern["id"],
                                    target_ref=identitySDO["id"])

    rel9 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO["id"],
                                    target_ref=attack_pattern["id"])

    rel10 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO["id"],
                                    target_ref=MalwareSDO["id"])

    rel11 = stix2.v21.Relationship(relationship_type="uses",
                                    source_ref=MalwareSDO["id"],
                                    target_ref=attack_pattern["id"])

    rel12 = stix2.v21.Relationship(relationship_type="remediates",
                                    source_ref=CoASDO["id"],
                                    target_ref=attack_pattern["id"])

    # Sightning relationship between identitySDO and the indicator of compromise
    sig = stix2.v21.Sighting(created_by_ref=identitySDO["id"],
                                sighting_of_ref=IoCSDO["id"],
                                count=1,
                                observed_data_refs=[ObservedDataSDO["id"]])

    # Quirks for using custom "dialects" with cti-python-stix2
    # https://github.com/oasis-open/cti-python-stix2/issues/501
    # https://github.com/oasis-open/cti-python-stix2/issues/429
    # https://github.com/oasis-open/cti-python-stix2/issues/558
    # https://github.com/oasis-open/cti-python-stix2/issues/543
    # https://github.com/oasis-open/cti-python-stix2/pull/503

    bundle = stix2.v21.Bundle([rel2,
                                rel3,
                                rel4,
                                rel5,
                                rel6,
                                rel7,
                                rel8,
                                rel9,
                                rel10,
                                rel11,
                                TLP_RED,
                                reportSDO,
                                infraAttacker,
                                infraVictim,
                                attack_pattern,
                                coa_extension_definition,
                                CoASDO,
                                IoCSDO,
                                identitySDO,
                                sig,
                                ObservedDataSDO,
                                attackerIpSCO,
                                impactedHostIpSCO,
                                trafficSCO,
                                MalwareSDO],
                                allow_custom=True)

    json_string_stix = bundle.serialize(pretty=True)

    # Encode the string as base64
    base64_bytes = base64.b64encode(json_string_stix.encode('utf-8'))

    # Decode the base64 bytes to a string
    base64_string_stix = base64_bytes.decode('utf-8')

    logger.info(f"Produced STIX Report")

    return json_string_stix, base64_string_stix

def getSTIXReport_ransomware(global_scope):

    threat_name = global_scope.get("threat_label")
    #attacker_ip = global_scope.get("RansomwareAlertSourceIp")

    if ENABLE_PRIVATE_ARTIFACTS_SHARING == "1":
        impacted_host_ip = global_scope.get("RansomwareAlertSourceIp")
    else:
        impacted_host_ip = "X.X.X.X"

    organization_id = global_scope.get("organization_id")

    mitre_enterprise_attack_file = stix2.MemoryStore()
    mitre_enterprise_attack_file.load_from_file("enterprise-attack.json")

    timestamp_now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    coa_extension_definition_file = stix2.MemoryStore()
    coa_extension_definition_file.load_from_file("stix_coa_extension_definition.json")
    coa_extension_definition = coa_extension_definition_file.get("extension-definition--1e1c1bd7-c527-4215-8e18-e199e74da57c")

    attack_pattern = mitre_enterprise_attack_file.query([
        stix2.Filter("external_references.external_id", "=", "T1134"),
        stix2.Filter("type", "=", "attack-pattern")
    ])[0]

    kill_chain_phases = attack_pattern.kill_chain_phases

    identitySDO = stix2.Identity(name=f"Organization ID.{organization_id}",
                                identity_class="organization")

    #attackerIpSCO = stix2.v21.IPv4Address(value=attacker_ip)

    impactedHostIpSCO = stix2.v21.IPv4Address(value=impacted_host_ip,
                                                object_marking_refs=[TLP_RED["id"]])

    # trafficSCO = stix2.v21.NetworkTraffic(src_ref=impactedHostIpSCO["id"],
    #                                         dst_ref= attackerIpSCO["id"],
    #                                         protocols=["tcp"],
    #                                         dst_port=22)

    # #Observed data
    # ObservedDataSDO = stix2.v21.ObservedData(object_refs=
    #                                 [attackerIpSCO["id"],
    #                                 impactedHostIpSCO["id"],
    #                                 trafficSCO["id"]],
    #                                 first_observed = timestamp_now,
    #                                 last_observed = timestamp_now,
    #                                 number_observed = 1)

    # Malware
    MalwareSDO = stix2.v21.Malware(name=threat_name,
                                    is_family=False,
                                    kill_chain_phases=kill_chain_phases)

    # Indicator of compromise
    IoCSDO = stix2.v21.Indicator(indicator_types=["malicious-activity"],
                                valid_from=timestamp_now,
                                pattern_type="None",
                                pattern="None",
                                name="Malicious traffic",
                                description="Traffic related to ransomware activity",
                                kill_chain_phases=kill_chain_phases,
                                labels= ["malicious-activity"])

    infraVictim = stix2.v21.Infrastructure(name = "Victim host",
                                        description = "The host being victim of a ransomware",
                                        infrastructure_types = ["workstation"])

    infraAttacker = stix2.v21.Infrastructure(name = "Attacker host",
                                        description = "The command and control server of the ransom campaign",
                                        infrastructure_types = ["command-and-control", "botnet"])

    # Course of action
    CoASDO = stix2.v21.CourseOfAction(description="CACAO Playbook course of action",
                                    name="CACAO playbook",
                                    extensions={
                                        coa_extension_definition["id"] : {
                                            "extension_type": "property-extension",
                                            # "created": timestamp_now,
                                            # "modified": timestamp_now,
                                            "playbook_standard": "playbook_standard",
                                            "playbook_bin": global_scope["cacao_playbook_base64"],
                                        },
                                    },
                                    created_by_ref=identitySDO["id"])

    # Report
    reportSDO = stix2.v21.Report(name="Ransomware remediation",
                            published=timestamp_now,
                            object_refs=[IoCSDO["id"], identitySDO["id"] ]) # CoASDO["id"], ext["id"]

    # # Relationship between course of action and indicator of compromise
    # rel = stix2.v21.Relationship(relationship_type="mitigates", #remediates
    #                                 source_ref=CoASDO["id"],
    #                                 target_ref=IoCSDO["id"],
    #                                 created_by_ref=identitySDO["id"])

    # Relationship between identitySDO and the report
    rel2 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=identitySDO["id"],
                                    target_ref=reportSDO["id"],
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of compromise and malware
    rel3 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of report and malware
    rel4 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=reportSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    rel5 = stix2.v21.Relationship(relationship_type="consists-of",
                                    source_ref=infraVictim["id"],
                                    target_ref=impactedHostIpSCO["id"])

    # rel6 = stix2.v21.Relationship(relationship_type="consists-of",
    #                                 source_ref=infraAttacker["id"],
    #                                 target_ref=attackerIpSCO["id"])

    rel7 = stix2.v21.Relationship(relationship_type="communicates-with",
                                    source_ref=infraVictim["id"],
                                    target_ref=infraAttacker["id"])

    rel8 = stix2.v21.Relationship(relationship_type="targets",
                                    source_ref=attack_pattern["id"],
                                    target_ref=identitySDO["id"])

    rel9 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO["id"],
                                    target_ref=attack_pattern["id"])

    rel10 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO["id"],
                                    target_ref=MalwareSDO["id"])

    rel11 = stix2.v21.Relationship(relationship_type="uses",
                                    source_ref=MalwareSDO["id"],
                                    target_ref=attack_pattern["id"])

    rel12 = stix2.v21.Relationship(relationship_type="remediates",
                                    source_ref=CoASDO["id"],
                                    target_ref=attack_pattern["id"])

    # Sightning relationship between identitySDO and the indicator of compromise
    # sig = stix2.v21.Sighting(created_by_ref=identitySDO["id"],
    #                             sighting_of_ref=IoCSDO["id"],
    #                             count=1,
    #                             observed_data_refs=[ObservedDataSDO["id"]])

    # Quirks for using custom "dialects" with cti-python-stix2
    # https://github.com/oasis-open/cti-python-stix2/issues/501
    # https://github.com/oasis-open/cti-python-stix2/issues/429
    # https://github.com/oasis-open/cti-python-stix2/issues/558
    # https://github.com/oasis-open/cti-python-stix2/issues/543
    # https://github.com/oasis-open/cti-python-stix2/pull/503

    bundle = stix2.v21.Bundle([rel2,
                                rel3,
                                rel4,
                                rel5,
                                #rel6,
                                rel7,
                                rel8,
                                rel9,
                                rel10,
                                rel11,
                                TLP_RED,
                                reportSDO,
                                infraAttacker,
                                infraVictim,
                                attack_pattern,
                                coa_extension_definition,
                                CoASDO,
                                IoCSDO,
                                identitySDO,
                                #sig,
                                #ObservedDataSDO,
                                #attackerIpSCO,
                                impactedHostIpSCO,
                                #trafficSCO,
                                MalwareSDO],
                                allow_custom=True)

    json_string_stix = bundle.serialize(pretty=True)

    # Encode the string as base64
    base64_bytes = base64.b64encode(json_string_stix.encode('utf-8'))

    # Decode the base64 bytes to a string
    base64_string_stix = base64_bytes.decode('utf-8')

    logger.info(f"Produced STIX Report")

    return json_string_stix, base64_string_stix

def getSTIXReport_botnet(global_scope):

    threat_name = global_scope.get("threat_label")
    attacker_ip = global_scope.get("attacker_ip")
    c2serversPort = global_scope.get("c2serversPort")
    if ENABLE_PRIVATE_ARTIFACTS_SHARING == "1":
        impacted_host_ip = global_scope.get("impacted_host_ip")
    else:
        impacted_host_ip = "X.X.X.X"

    organization_id = global_scope.get("organization_id")

    mitre_enterprise_attack_file = stix2.MemoryStore()
    mitre_enterprise_attack_file.load_from_file("enterprise-attack.json")

    timestamp_now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    coa_extension_definition_file = stix2.MemoryStore()
    coa_extension_definition_file.load_from_file("stix_coa_extension_definition.json")
    coa_extension_definition = coa_extension_definition_file.get("extension-definition--1e1c1bd7-c527-4215-8e18-e199e74da57c")

    attack_pattern = mitre_enterprise_attack_file.query([
        stix2.Filter("external_references.external_id", "=", "T1134"),
        stix2.Filter("type", "=", "attack-pattern")
    ])[0]

    kill_chain_phases = attack_pattern.kill_chain_phases

    identitySDO = stix2.Identity(name=f"Organization ID.{organization_id}",
                                identity_class="organization")

    # Pattern used by the indicator of compromise
    IoCPattern = ("[network-traffic:dst_ref.type = 'ipv4-addr' AND "
                    f"network-traffic:dst_ref.value = '{attacker_ip}' AND "
                    f"network-traffic:dst_port.value = '{c2serversPort}']")

    attackerIpSCO = stix2.v21.IPv4Address(value=attacker_ip)

    impactedHostIpSCO = stix2.v21.IPv4Address(value=impacted_host_ip,
                                                object_marking_refs=[TLP_RED["id"]])

    trafficSCO = stix2.v21.NetworkTraffic(src_ref=impactedHostIpSCO["id"],
                                            dst_ref= attackerIpSCO["id"],
                                            protocols=["tcp"],
                                            dst_port=22)

    #Observed data
    ObservedDataSDO = stix2.v21.ObservedData(object_refs=
                                    [attackerIpSCO["id"],
                                    impactedHostIpSCO["id"],
                                    trafficSCO["id"]],
                                    first_observed = timestamp_now,
                                    last_observed = timestamp_now,
                                    number_observed = 1)

    # Malware
    MalwareSDO = stix2.v21.Malware(name=threat_name,
                                    is_family=False,
                                    kill_chain_phases=kill_chain_phases)

    # Indicator of compromise
    IoCSDO = stix2.v21.Indicator(indicator_types=["malicious-activity"],
                                pattern_type="stix",
                                pattern=IoCPattern,
                                valid_from=timestamp_now,
                                name="Command and control traffic",
                                description="This traffic indicates the source host is "
                                "trying to reach to his command and control server",
                                kill_chain_phases=kill_chain_phases,
                                labels= ["malicious-activity"])

    infraVictim = stix2.v21.Infrastructure(name = "Victim host",
                                        description = "The host being part of the botnet",
                                        infrastructure_types = ["workstation"])

    infraAttacker = stix2.v21.Infrastructure(name = "Attacker host",
                                        description = "The command and control server of the botnet",
                                        infrastructure_types = ["command-and-control", "botnet"])

    # Course of action
    CoASDO = stix2.v21.CourseOfAction(description="CACAO Playbook course of action",
                                    name="CACAO playbook",
                                    extensions={
                                        coa_extension_definition["id"] : {
                                            "extension_type": "property-extension",
                                            # "created": timestamp_now,
                                            # "modified": timestamp_now,
                                            "playbook_standard": "playbook_standard",
                                            "playbook_bin": global_scope["cacao_playbook_base64"],
                                        },
                                    },
                                    created_by_ref=identitySDO["id"])

    # Report
    reportSDO = stix2.v21.Report(name="Botnet remediation",
                            published=timestamp_now,
                            object_refs=[IoCSDO["id"], identitySDO["id"] ]) # CoASDO["id"], ext["id"]

    # # Relationship between course of action and indicator of compromise
    # rel = stix2.v21.Relationship(relationship_type="mitigates", #remediates
    #                                 source_ref=CoASDO["id"],
    #                                 target_ref=IoCSDO["id"],
    #                                 created_by_ref=identitySDO["id"])

    # Relationship between identitySDO and the report
    rel2 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=identitySDO["id"],
                                    target_ref=reportSDO["id"],
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of compromise and malware
    rel3 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of report and malware
    rel4 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=reportSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    rel5 = stix2.v21.Relationship(relationship_type="consists-of",
                                    source_ref=infraVictim["id"],
                                    target_ref=impactedHostIpSCO["id"])

    rel6 = stix2.v21.Relationship(relationship_type="consists-of",
                                    source_ref=infraAttacker["id"],
                                    target_ref=attackerIpSCO["id"])

    rel7 = stix2.v21.Relationship(relationship_type="communicates-with",
                                    source_ref=infraVictim["id"],
                                    target_ref=infraAttacker["id"])

    rel8 = stix2.v21.Relationship(relationship_type="targets",
                                    source_ref=attack_pattern["id"],
                                    target_ref=identitySDO["id"])

    rel9 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO["id"],
                                    target_ref=attack_pattern["id"])

    rel10 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO["id"],
                                    target_ref=MalwareSDO["id"])

    rel11 = stix2.v21.Relationship(relationship_type="uses",
                                    source_ref=MalwareSDO["id"],
                                    target_ref=attack_pattern["id"])

    rel12 = stix2.v21.Relationship(relationship_type="remediates",
                                    source_ref=CoASDO["id"],
                                    target_ref=attack_pattern["id"])

    # Sightning relationship between identitySDO and the indicator of compromise
    sig = stix2.v21.Sighting(created_by_ref=identitySDO["id"],
                                sighting_of_ref=IoCSDO["id"],
                                count=1,
                                observed_data_refs=[ObservedDataSDO["id"]])

    # Quirks for using custom "dialects" with cti-python-stix2
    # https://github.com/oasis-open/cti-python-stix2/issues/501
    # https://github.com/oasis-open/cti-python-stix2/issues/429
    # https://github.com/oasis-open/cti-python-stix2/issues/558
    # https://github.com/oasis-open/cti-python-stix2/issues/543
    # https://github.com/oasis-open/cti-python-stix2/pull/503
    #

    bundle = stix2.v21.Bundle([rel2,
                                rel3,
                                rel4,
                                rel5,
                                rel6,
                                rel7,
                                rel8,
                                rel9,
                                rel10,
                                rel11,
                                TLP_RED,
                                reportSDO,
                                infraAttacker,
                                infraVictim,
                                attack_pattern,
                                coa_extension_definition,
                                CoASDO,
                                IoCSDO,
                                identitySDO,
                                sig,
                                ObservedDataSDO,
                                attackerIpSCO,
                                impactedHostIpSCO,
                                trafficSCO,
                                MalwareSDO],
                                allow_custom=True)

    json_string_stix = bundle.serialize(pretty=True)

    # Encode the string as base64
    base64_bytes = base64.b64encode(json_string_stix.encode('utf-8'))

    # Decode the base64 bytes to a string
    base64_string_stix = base64_bytes.decode('utf-8')

    logger.info(f"Produced STIX Report")

    return json_string_stix, base64_string_stix

def getSTIXReport_test():

    mem = stix2.MemoryStore()

    threat_name = "test"
    attacker_ip = "1.1.1.1"
    c2serversPort = "22"

    impacted_host_ip = "10.10.10.20"

    identitySDO = stix2.Identity(name='Politecnico di Torino',
                                    identity_class='organization')

    # ext = stix2.v21.ExtensionDefinition(created_by_ref=identitySDO["id"],
    #                                     name="CACAO Course of Action",
    #                                     schema="https://www.oasis.org/cacao.json",
    #                                     version="0.1",
    #                                     extension_types=["property-extension"],
    #                                     extension_properties=["cacao_playbook"])

    # COASDO_EXTENSION_ID = ext["id"]

    # # Declare extension class to gain STIX python library ability to detect when wrong extension parameters are
    # # given to a SDO. Read here: https://stix2.readthedocs.io/en/latest/guide/extensions.html
    # @stix2.v21.CustomExtension(
    #     COASDO_EXTENSION_ID, [
    #         ('cacao_playbook', stix2.properties.DictionaryProperty(required=True))
    #     ],
    # )
    # class CACAOPropertyExtension:
    #     extension_type = 'property-extension'

    # Pattern used by the indicator of compromise
    IoCPattern = ("[network-traffic:dst_ref.type = 'ipv4-addr' AND "
                    f"network-traffic:dst_ref.value = '{attacker_ip}' AND "
                    f"network-traffic:dst_port.value = '{c2serversPort}']")

    # CACAO playbook of the course of action in response to a sigthning of an indicator
    remediationPlaybook = {} # todo

    attackerIpSCO = stix2.v21.IPv4Address(value=attacker_ip)
    impactedHostIpSCO = stix2.v21.IPv4Address(value=impacted_host_ip)

    trafficSCO = stix2.v21.NetworkTraffic(src_ref=impactedHostIpSCO["id"],
                                            dst_ref= attackerIpSCO["id"],
                                            protocols=["tcp"],
                                            dst_port=22)

    #Observed data
    ObservedDataSDO = stix2.v21.ObservedData(object_refs=[attackerIpSCO["id"],
                                    impactedHostIpSCO["id"],
                                    trafficSCO["id"]],
                                    first_observed="2020-02-01T12:34:55Z",
                                    last_observed="2020-02-01T12:34:57Z",
                                    number_observed=1)

    # Malware
    MalwareSDO = stix2.v21.Malware(name=threat_name,
                                    is_family=False,
                                    kill_chain_phases=[{
                                        "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                        "phase_name": "Exploit"}])

    # Indicator of compromise
    IoCSDO = stix2.v21.Indicator(indicator_types=['malicious-activity'],
                                pattern_type="stix",
                                pattern=IoCPattern,
                                valid_from="2020-02-01T12:34:56Z",
                                name="Command and control traffic",
                                description="This traffic indicates the source host is "
                                "trying to reach to his command and control server",
                                kill_chain_phases=[{
                                        "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                                        "phase_name": "Command and Control"}],
                                labels= ["malicious-activity"])

    # # Course of action
    # CoASDO = stix2.v21.CourseOfAction(description="This a CACAO Playbook course of action for a rule of type level 4 filtering ",
    #                                 name="CACAO Playbook",
    #                                 extensions={
    #                                     COASDO_EXTENSION_ID : {
    #                                         'extension_type': 'property-extension',
    #                                         "cacao_playbook": remediationPlaybook.toDict()
    #                                     },
    #                                 },
    #                                 created_by_ref=identitySDO["id"])

    # Report
    reportSDO = stix2.v21.Report(name="Botnet remediation",
                            published="2022-02-10T12:34:56Z",
                            object_refs=[IoCSDO["id"], identitySDO["id"] ]) # CoASDO["id"], ext["id"]

    # # Relationship between course of action and indicator of compromise
    # rel = stix2.v21.Relationship(relationship_type="mitigates", #remediates
    #                                 source_ref=CoASDO["id"],
    #                                 target_ref=IoCSDO["id"],
    #                                 created_by_ref=identitySDO["id"])

    # Relationship between identitySDO and the report
    rel2 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=identitySDO["id"],
                                    target_ref=reportSDO["id"],
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of compromise and malware
    rel3 = stix2.v21.Relationship(relationship_type="indicates",
                                    source_ref=IoCSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    # Relationship between indicator of report and malware
    rel4 = stix2.v21.Relationship(relationship_type="refers-to",
                                    source_ref=reportSDO.id,
                                    target_ref=MalwareSDO.id,
                                    created_by_ref=identitySDO["id"])

    # Sightning relationship between identitySDO and the indicator of compromise
    sig = stix2.v21.Sighting(created_by_ref=identitySDO["id"],
                                sighting_of_ref=IoCSDO["id"],
                                count=1,
                                observed_data_refs=[ObservedDataSDO["id"]])

    # mem.add([rel2, rel3, rel4, reportSDO, IoCSDO, identitySDO, sig, ObservedDataSDO, attackerIpSCO, impactedHostIpSCO, trafficSCO, MalwareSDO]) #CoASDO, rel, ext
    bundle = stix2.v21.Bundle([rel2, rel3, rel4, reportSDO, IoCSDO, identitySDO, sig, ObservedDataSDO, attackerIpSCO, impactedHostIpSCO, trafficSCO, MalwareSDO])

    json_stix = bundle.serialize(pretty=True)

    # Encode the string as base64
    base64_bytes = base64.b64encode(json_stix.encode('utf-8'))

    # Decode the base64 bytes to a string
    base64_string = base64_bytes.decode('utf-8')

    logger.info(f"Produced test STIX Report")

    return json_stix, base64_string

def getSTIXReport_test_standalone():


        mitre_enterprise_attack_file = stix2.MemoryStore()
        mitre_enterprise_attack_file.load_from_file("enterprise-attack.json")

        timestamp_now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        mem = stix2.MemoryStore()

        threat_name = "test"
        attacker_ip = "1.1.1.1"
        c2serversPort = "22"

        impacted_host_ip = "10.10.10.20"

        coa_extension_definition_file = stix2.MemoryStore()
        coa_extension_definition_file.load_from_file("stix_coa_extension_definition.json")
        coa_extension_definition = coa_extension_definition_file.get("extension-definition--1e1c1bd7-c527-4215-8e18-e199e74da57c")
        mem.add(coa_extension_definition)

        attack_pattern = mitre_enterprise_attack_file.query([
            stix2.Filter("external_references.external_id", "=", "T1134"),
            stix2.Filter("type", "=", "attack-pattern")
        ])[0]
        mem.add(attack_pattern)

        kill_chain_phases = attack_pattern.kill_chain_phases

        identitySDO = stix2.Identity(name=f"organization 1234",
                                    identity_class="organization")
        mem.add(identitySDO)


        # Pattern used by the indicator of compromise
        IoCPattern = ("[network-traffic:dst_ref.type = 'ipv4-addr' AND "
                        f"network-traffic:dst_ref.value = '{attacker_ip}' AND "
                        f"network-traffic:dst_port.value = '{c2serversPort}']")

        # CACAO playbook of the course of action in response to a sigthning of an indicator
        remediationPlaybook = {} # todo

        attackerIpSCO = stix2.v21.IPv4Address(value=attacker_ip)
        mem.add(attackerIpSCO)

        impactedHostIpSCO = stix2.v21.IPv4Address(value=impacted_host_ip,
                                                  object_marking_refs=[TLP_RED["id"]])
        mem.add(impactedHostIpSCO)

        trafficSCO = stix2.v21.NetworkTraffic(src_ref=impactedHostIpSCO["id"],
                                                dst_ref= attackerIpSCO["id"],
                                                protocols=["tcp"],
                                                dst_port=22)
        mem.add(trafficSCO)

        #Observed data
        ObservedDataSDO = stix2.v21.ObservedData(object_refs=
                                        [attackerIpSCO["id"],
                                        impactedHostIpSCO["id"],
                                        trafficSCO["id"]],
                                        first_observed = timestamp_now,
                                        last_observed = timestamp_now,
                                        number_observed = 1)
        mem.add(ObservedDataSDO)

        # Malware
        MalwareSDO = stix2.v21.Malware(name=threat_name,
                                        is_family=False,
                                        kill_chain_phases=kill_chain_phases)
        mem.add(MalwareSDO)

        # Indicator of compromise
        IoCSDO = stix2.v21.Indicator(indicator_types=["malicious-activity"],
                                    pattern_type="stix",
                                    pattern=IoCPattern,
                                    valid_from=timestamp_now,
                                    name="Command and control traffic",
                                    description="This traffic indicates the source host is "
                                    "trying to reach to his command and control server",
                                    kill_chain_phases=kill_chain_phases,
                                    labels= ["malicious-activity"])
        mem.add(IoCSDO)

        infraVictim = stix2.v21.Infrastructure(name = "Victim host",
                                            description = "The host being part of the botnet",
                                            infrastructure_types = ["workstation"])
        mem.add(infraVictim)

        infraAttacker = stix2.v21.Infrastructure(name = "Attacker host",
                                            description = "The command and control server of the botnet",
                                            infrastructure_types = ["command-and-control", "botnet"])
        mem.add(infraAttacker)

        # Course of action
        CoASDO = stix2.v21.CourseOfAction(description="CACAO Playbook course of action",
                                        name="CACAO playbook",
                                        extensions={
                                            coa_extension_definition["id"] : {
                                                "extension_type": "property-extension",
                                                # "created": timestamp_now,
                                                # "modified": timestamp_now,
                                                "playbook_standard": "playbook_standard",
                                                "playbook_bin": "aadfvadfv",
                                            },
                                        },
                                        created_by_ref=identitySDO["id"])
        mem.add(CoASDO)

        # Report
        reportSDO = stix2.v21.Report(name="Botnet remediation",
                                published=timestamp_now,
                                object_refs=[IoCSDO["id"], identitySDO["id"] ]) # CoASDO["id"], ext["id"]
        mem.add(reportSDO)

        # # Relationship between course of action and indicator of compromise
        # rel = stix2.v21.Relationship(relationship_type="mitigates", #remediates
        #                                 source_ref=CoASDO["id"],
        #                                 target_ref=IoCSDO["id"],
        #                                 created_by_ref=identitySDO["id"])

        # Relationship between identitySDO and the report
        rel2 = stix2.v21.Relationship(relationship_type="refers-to",
                                        source_ref=identitySDO["id"],
                                        target_ref=reportSDO["id"],
                                        created_by_ref=identitySDO["id"])
        mem.add(rel2)

        # Relationship between indicator of compromise and malware
        rel3 = stix2.v21.Relationship(relationship_type="indicates",
                                        source_ref=IoCSDO.id,
                                        target_ref=MalwareSDO.id,
                                        created_by_ref=identitySDO["id"])
        mem.add(rel3)

        # Relationship between indicator of report and malware
        rel4 = stix2.v21.Relationship(relationship_type="refers-to",
                                        source_ref=reportSDO.id,
                                        target_ref=MalwareSDO.id,
                                        created_by_ref=identitySDO["id"])
        mem.add(rel4)

        rel5 = stix2.v21.Relationship(relationship_type="consists-of",
                                        source_ref=infraVictim["id"],
                                        target_ref=impactedHostIpSCO["id"])
        mem.add(rel5)

        rel6 = stix2.v21.Relationship(relationship_type="consists-of",
                                        source_ref=infraAttacker["id"],
                                        target_ref=attackerIpSCO["id"])
        mem.add(rel6)

        rel7 = stix2.v21.Relationship(relationship_type="communicates-with",
                                        source_ref=infraVictim["id"],
                                        target_ref=infraAttacker["id"])
        mem.add(rel7)

        rel8 = stix2.v21.Relationship(relationship_type="targets",
                                        source_ref=attack_pattern["id"],
                                        target_ref=identitySDO["id"])
        mem.add(rel8)

        rel9 = stix2.v21.Relationship(relationship_type="indicates",
                                        source_ref=IoCSDO["id"],
                                        target_ref=attack_pattern["id"])
        mem.add(rel9)

        rel10 = stix2.v21.Relationship(relationship_type="indicates",
                                        source_ref=IoCSDO["id"],
                                        target_ref=MalwareSDO["id"])
        mem.add(rel10)

        rel11 = stix2.v21.Relationship(relationship_type="uses",
                                        source_ref=MalwareSDO["id"],
                                        target_ref=attack_pattern["id"])
        mem.add(rel11)

        rel12 = stix2.v21.Relationship(relationship_type="remediates",
                                        source_ref=CoASDO["id"],
                                        target_ref=attack_pattern["id"])
        mem.add(rel12)

        # Sightning relationship between identitySDO and the indicator of compromise
        sig = stix2.v21.Sighting(created_by_ref=identitySDO["id"],
                                    sighting_of_ref=IoCSDO["id"],
                                    count=1,
                                    observed_data_refs=[ObservedDataSDO["id"]])
        mem.add(sig)

        mem.add(TLP_RED)

        mem.save_to_file("test.json")

if __name__ == "__main__":
    os.chdir("./rr-tool")
    getSTIXReport_test_standalone()
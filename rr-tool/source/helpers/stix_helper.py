import stix2


def getSTIXReport(attacker_ip, c2serversPort, impacted_host_ip, threat_name):

        mem = stix2.MemoryStore()

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

        json_stix = bundle.serialize()

        return json_stix
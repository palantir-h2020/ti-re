import irAPI
import logging
import portalAPI
import settings

def fbm_function(alert):
    ip = alert[settings.TI_SYSLOG_VICTIM_IP_FIELD_NAME]
    logging.info('Incident response API: notifying data breach on host with IP '+ip)
    portalAPI.notify_portal(componentType="Recommendation and Remediation",
                            componentId="0",
                            actionName="Call Incident Response",
                            actionDescription="Reaction to following alert: "+str(alert),
                            onips=ip)
    irAPI.notify_ir("brute-force-attack",ip,"Data breach attempt detected: "+str(alert))


FunctionMappings = {
    "fbm_function": fbm_function
}
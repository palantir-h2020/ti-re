import connectors
from connectors import portal, ir

from helpers.logging_helper import get_child_logger

logger = get_child_logger('recipe-interpreter', 'custom-functions')


def fbm_call(alert, alert_source_ip):
    logger.info('Incident response API: notifying data breach on host with IP ' + alert_source_ip)
    portal.notify(component_type="Recommendation and Remediation",
                  component_id="0",
                  action_name="Call Incident Response",
                  action_description="Reaction to following alert: " + str(alert),
                  on_ips=[alert_source_ip])
    ir.notify("brute-force-attack", alert_source_ip, "Data breach attempt detected: " + str(alert))


FunctionMappings = {
    "fbm_call": fbm_call
}

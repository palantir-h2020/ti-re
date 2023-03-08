from connectors import portal, ir

from helpers.logging_helper import get_child_logger

logger = get_child_logger('recipe-interpreter', 'custom-functions')


def fbm_call(alert, alert_source_ip):

    portal.notify(component_type="Recommendation and Remediation",
                  component_id="0",
                  action_name="Call Incident Response",
                  action_description="Reaction to following alert: " + str(alert),
                  on_ips=[alert_source_ip])

    ir.notify("brute-force-attack", alert_source_ip, "Data breach attempt detected: " + str(alert))

def fbm_call_ransomware(alert, alert_source_ip):

    portal.notify(component_type="Recommendation and Remediation",
                  component_id="0",
                  action_name="Call Incident Response",
                  action_description="Reaction to following alert: " + str(alert),
                  on_ips=[alert_source_ip])

    ir.notify_ransomware("ransomware",
                        alert_source_ip,
                        "Ransomware detected: " + str(alert),
                        alert.get("wazuh_agent_id"))

FunctionMappings = {
    "fbm_call": fbm_call,
    "fbm_call_ransomware": fbm_call_ransomware
}

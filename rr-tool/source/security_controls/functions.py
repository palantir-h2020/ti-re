from security_controls.iptables.translator import iptables_command_generator

from helpers.logging_helper import get_logger

logger = get_logger('security-controls')


# this function is a stub, just return the rule
# noinspection PyUnusedLocal
def generic_level_7_filter_command_generator(rule, *args):

    return rule


# this function is a stub, just return the rule
# noinspection PyUnusedLocal
def generic_network_traffic_monitor_command_generator(rule, *args):

    return rule


# noinspection PyUnusedLocal
def testFunction(*args):
    del args
    if not hasattr(testFunction, "counter"):
        testFunction.counter = 0

    if testFunction.counter == 0:
        return "rule 1"
    elif testFunction.counter == 1:
        return "rule 2"
    elif testFunction.counter == 2:
        return "rule 3"

    testFunction.counter += 1


FunctionMappings = {
    "iptables": iptables_command_generator,
    "generic_level_7_filter": generic_level_7_filter_command_generator,
    "generic_network_traffic_monitor": generic_network_traffic_monitor_command_generator
}

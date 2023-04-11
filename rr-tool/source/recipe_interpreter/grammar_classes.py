from dataclasses import dataclass
from typing import Optional
from . import custom_functions
import settings
from helpers.logging_helper import get_logger
from .support_functions import getVarFromContext

logger = get_logger('recipe_interpreter')

#### Helper classes ####

# these, together with the hierarchical ones, are NOT grammar rules, that is, are not meant to be used
# as classes for their respective grammar rules. So are not used to generate the Model, a.k.a the AST
# of the Recipe, in fact they are neither passed to textx for the Meta-model generation. Instead
# they are just used for passing base functionalities to the Grammar rules' classes, such as logger
# or, for the hierarchical ones, for having a base class for every child rule, such as with
# Statement -> commands.

class LogClass:
    """Base class with logger capabilities"""

    def info(self):
        print(f"+{self.__class__.__name__}+")

#### Hierarchical classes ####

#  needed only for strict typing of grammar rules' class attributes

class Statement(LogClass):
    def run(self, *args):
        pass
    def testRun(self, *args):
        pass

class FunctionCall(Statement):
    pass

##

@dataclass
class VarReferenceOrString:
    """Grammar rule defining an abstract container which
       can contain both variables of type VarReference and string
       raw values
    """

    parent: object
    value: object

    def getValue(self, scope):
        if isinstance(self.value, VarReference):
            return self.value.getValue(scope)
        else:
            return self.value

@dataclass
class VarReference:
    """Grammar rule defining variables in the Recipe language"""

    parent: object
    value: str

    def getValue(self, scope):
        return getVarFromContext(self.value, scope)

@dataclass
class Recipe(LogClass):
    """Grammar rule for the Recipe root object, containing a list of Statements"""

    statements: list[Statement]

    def run(self, scope, remediator):

        for el in self.statements:
            el.run(scope, remediator)

    def testRun(self, scope):
        super().info()
        print("Running the recipe")

        for el in self.statements:
            el.testRun(scope)

        print(f"Recipe end")

@dataclass
class Iteration(Statement):
    """ Grammar rule for the iteration Recipe language construct
        Sample expression: [check recipe examples]
    """

    parent: object
    iterationExpression: VarReference
    statements: list[Statement]

    def run(self, scope, remediator):

        iterateScope = { "outerScope": scope }

        # for debug only, it's not a functional part
        iteration_list=self.iterationExpression.getValue(scope)
        print(f"Iteration list: {iteration_list}")

        for item in self.iterationExpression.getValue(scope):
            iterateScope["iteration_element"] = item
            for el in self.statements:
                el.run(iterateScope, remediator)

        print(f"End iteration")

    def testRun(self, scope):
        super().info()

        iterateScope = { "outerScope": scope }
        print(f"Iterating on: {self.iterationExpression.getValue(scope)}")

        for item in self.iterationExpression.getValue(scope):
            iterateScope["iteration_element"] = item
            for el in self.statements:
                el.testRun(iterateScope)

        print(f"End iteration")

@dataclass
class Condition(Statement):
    """ Grammar rule for the condition Recipe language construct
        Sample expression: [check recipe examples]
    """

    parent: object
    notClause: bool
    conditionExpression: VarReferenceOrString
    ifStatements: list[Statement]
    elseStatements: list[Statement]


    def run(self, scope, remediator):
        conditionScope = { "outerScope": scope }

        if self.conditionExpression.getValue(scope) is not self.notClause:

            for el in self.ifStatements:
                el.run(conditionScope, remediator)

        elif len(self.elseStatements) > 0:

            for el in self.elseStatements:
                el.run(conditionScope, remediator)

    def testRun(self, scope):
        super().info()

        conditionScope = { "outerScope": scope }

        print(f"Not clause: {self.notClause}")
        print(f"Condition expression: {self.conditionExpression.getValue(scope)}")

        print("If block")

        for el in self.ifStatements:
            el.testRun(conditionScope)

        print(f"End if block")

        if len(self.elseStatements) > 0:
            print("Else block")

            for el in self.elseStatements:
                el.testRun(conditionScope)

            print(f"End else block")

@dataclass
class ListPaths(FunctionCall):
    """ Grammar rule for the "list_paths" Recipe language instruction
        Sample expression: list_paths from impacted_host to 'attacker'
    """

    parent: object
    sourceExpression: VarReferenceOrString
    destinationExpression: VarReferenceOrString

    def run(self, scope, remediator):

        source = self.sourceExpression.getValue(scope)
        destination = self.destinationExpression.getValue(scope)
        logger.info("list_paths from " + f"{source}" + " to " + f"{destination}")

        try:
            scope["path_list"] = remediator.service_graph_instance.list_paths(source, destination)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Source: {self.sourceExpression.getValue(scope)}, "
                f"Destination: {self.destinationExpression.getValue(scope)}")

@dataclass
class FindNode(FunctionCall):
    """ Grammar rule for the "find_node" Recipe language instruction
        Sample expression: find_node of type 'firewall' in network_path with 'level_4_filtering'
    """

    parent: object
    nodeTypeExpression: VarReferenceOrString
    networkPathExpression: VarReferenceOrString
    nodeCapabilityExpression: Optional[VarReferenceOrString] # from Python 3.10 also VarReferenceOrString | None

    def run(self, scope, remediator):

        nodeType = self.nodeTypeExpression.getValue(scope)
        networkPath = self.networkPathExpression.getValue(scope)

        # for now supporting only one capability maximum in input
        if self.nodeCapabilityExpression is not None:
            nodeCapability = self.nodeCapabilityExpression.getValue(scope)
            nodeCapabilities = [nodeCapability]
            logger.info("find_node of type " + f"{nodeType}" + " in " + f"{networkPath}" +
                            " with " + f"{nodeCapability}")
        else:
            nodeCapabilities = []
            logger.info("find_node of type " + f"{nodeType}" + " in " + f"{networkPath}")

        try:
            found_node = remediator.service_graph_instance.find_node_in_path(networkPath, nodeType, nodeCapabilities)
        except Exception as ex:
            raise ex  # just rethrow it for now

        if found_node != "Not found":
            scope["found_node"] = found_node
            scope["found"] = True
        else:
            scope["found_node"] = None
            scope["found"] = False

    def testRun(self, scope):
        super().info()
        print(f"Node type: {self.nodeTypeExpression.getValue(scope)}, "
                f"Path: {self.networkPathExpression.getValue(scope)}, "
                f"""Node capability: {'capability not present' if self.nodeCapabilityExpression is
                                        None else self.nodeCapabilityExpression.getValue(scope)}""")

@dataclass
class AddFirewall(FunctionCall):
    """ Grammar rule for the "add_firewall" Recipe language instruction
        Sample expression: add_firewall behind impacted_host in network_path with 'level_4_filtering'
    """

    parent: object
    impactedNodeExpression: VarReferenceOrString
    networkPathExpression: VarReferenceOrString
    filteringCapabilitiesExpression: Optional[VarReferenceOrString] # from Python 3.10 also VarReferenceOrString | None

    def run(self, scope, remediator):

        impactedNode = self.impactedNodeExpression.getValue(scope)
        networkPath = self.networkPathExpression.getValue(scope)

        # for now supporting only one capability maximum in input
        if self.filteringCapabilitiesExpression is not None:
            filteringCapability = self.filteringCapabilitiesExpression.getValue(scope)
            filteringCapabilities = [filteringCapability]
            logger.info("add_firewall behind " + f"{impactedNode}" + " in " + f"{networkPath}" + " with " +
                            f"{filteringCapability}")
        else:
            # by default assign level 4 and 7 capabilities if not specified otherwise
            filteringCapabilities = ["level_4_filtering", "level_7_filtering"]
            logger.info("add_firewall behind " + f"{impactedNode}" + " in " + f"{networkPath}")

        try:
            new_node = remediator.service_graph_instance.add_firewall(impactedNode, networkPath, filteringCapabilities)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        if self.filteringCapabilitiesExpression is not None:
            print(f"Impacted node with ip: {self.impactedNodeExpression.getValue(scope)}, "
                    f"Firewall positioning: {self.networkPathExpression.getValue(scope)}, "
                    f"Filtering type: {self.filteringCapabilitiesExpression.getValue(scope)}")
        else:
            print(f"Impacted node with ip: {self.impactedNodeExpression.getValue(scope)}, "
                    f"Firewall positioning: {self.networkPathExpression.getValue(scope)}")

@dataclass
class AddFilteringRules(FunctionCall):
    """ Grammar rule for the "add_filtering_rules" Recipe language instruction
        Sample expression: add_filtering_rules rules_level_4 to new_node
    """

    parent: object
    filteringRulesExpression: VarReference
    nodeExpression: VarReferenceOrString

    def run(self, scope, remediator):

        filteringRules = self.filteringRulesExpression.getValue(scope)
        node = self.nodeExpression.getValue(scope)
        logger.info("add_filtering_rules " + "rules" + " to " + f"{node}")

        #todo evaluation metrics
        '''
        try:
            translatedRules = []
            for rule in filteringRules:
                if rule["level"] == 4:
                    if settings.ENABLE_IDENTICAL_L4_FILTERING_RULE_SKIPPING == "1":
                        rule_existing = False
                        for existing_rule in remediator.service_graph_instance.get_filtering_rules(node, 4):
                            same_rule = True
                            for key in rule:
                                if rule[key] != existing_rule["policy"][key]:
                                    same_rule = False
                                    break
                            if same_rule:
                                rule_existing = same_rule
                                break
                        if rule_existing:
                            logger.info("Identical rule already applied, skipping...")
                            continue
                    generatedRule = remediator.generateRule("level_4_filtering", rule)
                    if generatedRule == "":
                        logger.error("Error generating concrete rule, skipping...")
                    else:
                        translatedRules.append(generatedRule)
                else:
                    translatedRules.append(remediator.generateRule("level_7_filtering", rule))

            remediator.service_graph_instance.add_filtering_rules(node, translatedRules)
        except Exception as ex:
            raise ex  # just rethrow it for now
        '''

    def testRun(self, scope):
        super().info()
        print(f"Level 7 rules reference: {self.filteringRulesExpression.getValue(scope)}, "
                f"Node: {self.nodeExpression.getValue(scope)}")

@dataclass
class AllowTraffic(FunctionCall):
    """ Grammar rule for the "allow_traffic" Recipe language instruction
        Sample expression: allow_traffic between impacted_host and 'switch3'
    """

    parent: object
    firstNodeExpression: VarReferenceOrString
    secondNodeExpression: VarReferenceOrString
    firewallNodeExpression: VarReferenceOrString

    def run(self, scope, remediator):


        firstNode = self.firstNodeExpression.getValue(scope)
        secondNode = self.secondNodeExpression.getValue(scope)
        firewallNode = self.firewallNodeExpression.getValue(scope)

        filteringRules = [
            {"level": 4, "victimIP": firstNode,
            "c2serversPort": "", "c2serversIP": secondNode,
            "proto": "", "action": "ALLOW"},
            {"level": 4, "victimIP": secondNode,
            "c2serversPort": "", "c2serversIP": firstNode,
            "proto": "", "action": "ALLOW"}
        ]

        logger.info("allow_traffic between " + f"{firstNode}" + " and " + f"{secondNode}")

        try:
            translatedRules = []
            for rule in filteringRules:
                if rule["level"] == 4:
                    if settings.ENABLE_IDENTICAL_L4_FILTERING_RULE_SKIPPING == "1":
                        rule_existing = False
                        for existing_rule in remediator.service_graph_instance.get_filtering_rules(firewallNode, 4):
                            same_rule = True
                            for key in rule:
                                if rule[key] != existing_rule["policy"][key]:
                                    same_rule = False
                                    break
                            if same_rule:
                                rule_existing = same_rule
                                break
                        if rule_existing:
                            logger.info("Identical rule already applied, skipping...")
                            continue
                    generatedRule = remediator.generateRule("level_4_filtering", rule)
                    if generatedRule == "":
                        logger.error("Error generating concrete rule, skipping...")
                    else:
                        translatedRules.append(generatedRule)
                else:
                    translatedRules.append(remediator.generateRule("level_7_filtering", rule))

            remediator.service_graph_instance.add_filtering_rules(firewallNode, translatedRules)
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"First node: {self.firstNodeExpression.getValue(scope)}, "
                f"Second node: {self.secondNodeExpression.getValue(scope)}")

@dataclass
class AddDnsPolicy(FunctionCall):
    """ Grammar rule for the "add_dns_policy" Recipe language instruction
        Sample expression: add_dns_policy for malicious_domain of type 'block_all_queries'
    """

    parent: object
    domainExpression: VarReferenceOrString
    policyTypeExpression: VarReferenceOrString

    def run(self, scope, remediator):

        domain = self.domainExpression.getValue(scope)
        policyType = self.policyTypeExpression.getValue(scope)
        logger.info("add_dns_policy for " + f"{domain}" + " of type " + f"{policyType}")

        try:
            remediator.service_graph_instance.add_dns_policy(domain, policyType)
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node: {self.domainExpression.getValue(scope)}, "
                f"Policy type: {self.policyTypeExpression.getValue(scope)}")

@dataclass
class AddNetworkMonitor(FunctionCall):
    """ Grammar rule for the "add_network_monitor" Recipe language instruction
        Sample expression: add_network_monitor behind impacted_host_ip in network_path
    """

    parent: object
    impactedNodeExpression: VarReferenceOrString
    networkPathExpression: VarReferenceOrString

    def run(self, scope, remediator):

        impactedNode = self.impactedNodeExpression.getValue(scope)
        networkPath = self.networkPathExpression.getValue(scope)
        logger.info("add_network_monitor behind" + f"{impactedNode}" + " in " + f"{networkPath}")

        try:
            new_node = remediator.service_graph_instance.add_network_monitor(impactedNode, networkPath)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Impacted node: {self.impactedNodeExpression.getValue(scope)}, "
                f"Network path: {self.networkPathExpression.getValue(scope)}")

@dataclass
class MoveNode(FunctionCall):
    """ Grammar rule for the "move" Recipe language instruction
        Sample expression:  move 'impacted_node' to 'reconfiguration_net'
    """

    parent: object
    nodeExpression: VarReferenceOrString
    subnetExpression: VarReferenceOrString

    def run(self, scope, remediator):

        node = self.nodeExpression.getValue(scope)
        subnet = self.subnetExpression.getValue(scope)
        logger.info("move " + f"{node}" + " to " + f"{subnet}")

        try:
            remediator.service_graph_instance.move(node, subnet)
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node: {self.nodeExpression.getValue(scope)}, "
                f"Destination subnet: {self.subnetExpression.getValue(scope)}")

@dataclass
class AddHoneypot(FunctionCall):
    """ Grammar rule for the "add_honeypot" Recipe language instruction
        Sample expression: add_honeypot with 'apache_vulnerability'
    """

    parent: object
    vulnerabilityExpression: VarReferenceOrString

    def run(self, scope, remediator):

        vulnerability = self.vulnerabilityExpression.getValue(scope)
        logger.info("add_honeypot with " + f"{vulnerability}")

        try:
            new_node = remediator.service_graph_instance.add_honeypot(vulnerability)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Type of honeypot: {self.vulnerabilityExpression.getValue(scope)}")

@dataclass
class Execute(FunctionCall):
    """ Grammar rule for the "execute" Recipe language instruction
        Sample expression: execute 'simpleFunction'
    """

    parent: object
    functionExpression: VarReferenceOrString
    functionArguments: list[VarReferenceOrString]

    def run(self, scope, remediator):

        functionName = self.functionExpression.getValue(scope)
        logger.info("execute " + f"{functionName}")

        try:
            systemFunction = custom_functions.FunctionMappings[functionName]
            #systemFunction("UnauthorizedAccessAlert")
            functionArguments = [el.getValue(scope) for el in self.functionArguments]
            systemFunction(*functionArguments)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Function to be executed: {self.functionExpression.getValue(scope)}")

@dataclass
class Shutdown(FunctionCall):
    """ Grammar rule for the "shutdown" Recipe language instruction
        Sample expression: shutdown 'compromised_host'
    """

    parent: object
    nodeExpression: VarReferenceOrString

    def run(self, scope, remediator):

        node = self.nodeExpression.getValue(scope)
        logger.info("shutdown " + f"{node}")

        try:
            remediator.service_graph_instance.shutdown(self.nodeExpression.getValue(scope))
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node to be shutdown: {self.nodeExpression.getValue(scope)}")

@dataclass
class Isolate(FunctionCall):
    """ Grammar rule for the "isolate" Recipe language instruction
        Sample expression: isolate 'compromised_host'
    """

    parent: object
    nodeExpression: VarReferenceOrString

    def run(self, scope, remediator):

        node = self.nodeExpression.getValue(scope)
        logger.info("isolate " + f"{node}")

        try:
            remediator.service_graph_instance.isolate(self.nodeExpression.getValue(scope))
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node to be isolated: {self.nodeExpression.getValue(scope)}")


recipe_classes = [Recipe, Iteration, Condition, ListPaths, FindNode, AddFirewall, AddFilteringRules,
                    AllowTraffic, AddDnsPolicy, AddNetworkMonitor, MoveNode, AddHoneypot,
                    Execute, Shutdown, Isolate, VarReferenceOrString, VarReference]
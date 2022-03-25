import os
from typing import Dict

import settings
import copy

import nltk
import sys
import json
import service_graph

from helpers.logging_helper import get_logger
from . import custom_functions
from security_controls import functions as security_controls_functions

logger = get_logger('recipe_interpreter')


class RecipeInterpreter:

    def __init__(self,
                 service_graph_instance,
                 global_scope,
                 capability_to_security_control_mappings) -> None:
        logger.info("Initializing Recipe Instruction Interpreter")
        self.recipeToRun = None
        self.service_graph_instance = service_graph_instance
        self.rowCursor = 0
        self.global_scope = global_scope
        self.capability_to_security_control_mappings = capability_to_security_control_mappings

    def list_paths(self, tokens, scope):
        if len(tokens) < 5:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        source = tokens[2].replace("'", "")
        if source == tokens[2]:
            source = self.getContextVar(source, scope)
        destination = tokens[4].replace("'", "")
        if destination == tokens[4]:
            destination = self.getContextVar(destination, scope)

        # logger post-tokenization
        logger.info(tokens[0] + " " + tokens[1] + " " + f"{source}" + " " + tokens[3] + " " + f"{destination}")

        scope["path_list"] = self.service_graph_instance.list_paths(source, destination)

    def find_node(self, tokens, scope):
        if len(tokens) < 6:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        nodeType = tokens[3].replace("'", "")  # node type to search for
        if nodeType == tokens[3]:
            nodeType = self.getContextVar(nodeType, scope)
        path = tokens[5].replace("'", "")  # where to search in for the node
        if path == tokens[5]:
            path = self.getContextVar(path, scope)

        # Support for additional "capability" argument
        if len(tokens) == 8:
            capability = tokens[7].replace("'", "")
            if capability == tokens[7]:
                capability = self.getContextVar(capability, scope)
            capabilities = [capability]  # for now supports only one capability as input
        else:
            capabilities = []

        try:

            logger.info(
                tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + f"{nodeType}" + " " + tokens[4] + " " + f"{path}")
            found_node = self.service_graph_instance.find_node_in_path(path, nodeType, capabilities)
            if found_node != "Not found":
                scope["found_node"] = found_node
                scope["found"] = True
            else:
                scope["found_node"] = None
                scope["found"] = False
        except Exception as ex:
            raise ex

    def add_node(self, tokens, scope):
        if len(tokens) < 8:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        nodeType = tokens[3].replace("'", "")
        if nodeType == tokens[3]:
            nodeType = self.getContextVar(nodeType, scope)
        node1 = tokens[5].replace("'", "")
        if node1 == tokens[3]:
            node1 = self.getContextVar(node1, scope)
        node2 = tokens[7].replace("'", "")
        if node2 == tokens[3]:
            node2 = self.getContextVar(node2, scope)

        try:
            logger.info(tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + f"{nodeType}" + " " + tokens[
                4] + " " + f"{node1}" + " " + tokens[6] + " " + f"{node2}")
            new_node = self.service_graph_instance.add_node(node1, node2, nodeType)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def add_firewall(self, tokens, scope):
        if len(tokens) < 5:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        node = tokens[2].replace("'", "")
        if node == tokens[2]:
            node = self.getContextVar(node, scope)
        path = tokens[4].replace("'", "")
        if path == tokens[4]:
            path = self.getContextVar(path, scope)

        # Support for additional "capability" argument
        if len(tokens) == 7:
            capability = tokens[6].replace("'", "")
            if capability == tokens[6]:
                capability = self.getContextVar(capability, scope)
            capabilities = [capability]  # for now supports only one capability as input
        else:
            capabilities = ["level_4_filtering", "level_7_filtering"]

        try:
            logger.info(
                tokens[0] + " " + tokens[1] + " " + f"{node}" + " " + tokens[3] + " " + f"{path}" + " " + tokens[5])
            new_node = self.service_graph_instance.add_firewall(node, path, capabilities)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def add_filtering_rules(self, tokens, scope):
        if len(tokens) < 4:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        node = tokens[3].replace("'", "")
        if node == tokens[3]:
            node = self.getContextVar(node, scope)
        rules = tokens[1].replace("'", "")
        if rules == tokens[1]:
            rules = self.getContextVar(rules, scope)

        try:
            logger.info(tokens[0] + " " + "rules" + " " + tokens[
                2] + " " + f"{node}")  # logger only "rules" otherwise output gets jammed

            # logger.debug(self.service_graph_instance.get_filtering_rules(node,4))
            # logger.debug(rules)

            translatedRules = []
            for rule in rules:
                if rule["level"] == 4:
                    if settings.ENABLE_IDENTICAL_L4_FILTERING_RULE_SKIPPING == "1":
                        rule_existing = False
                        for existing_rule in self.service_graph_instance.get_filtering_rules(node, 4):
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
                    generatedRule = self.generateRule("level_4_filtering", rule)
                    if generatedRule == "":
                        logger.error("Error generating concrete rule, skipping...")
                    else:
                        translatedRules.append(generatedRule)
                else:
                    translatedRules.append(self.generateRule("level_7_filtering", rule))

            self.service_graph_instance.add_filtering_rules(node, translatedRules)

        except Exception as ex:
            raise ex  # just rethrow it for now

    def generateRule(self, capability, policy):
        """Generates a rule for policy enforcement in the language specific of that security control with
        which the policy will be enforced. It taps into the SecurityControlToFunctionMappings dictionary in
        which each SecurityControl is mapped to a command generator function.
        Returns a dictionary representing the rule.
        """

        securityControlName = self.capability_to_security_control_mappings[capability]

        ruleGenerator = security_controls_functions.FunctionMappings[securityControlName]
        # this is a callable object, i.e. a function object

        if capability == "level_4_filtering":
            generatedRule = ruleGenerator(policy)
        else:
            generatedRule = ruleGenerator(policy)

        # check if the generation of rule was not successful
        if generatedRule == "":
            return ""

        newRule = {"type": capability,
                   "enforcingSecurityControl": securityControlName,
                   "rule": generatedRule,
                   "policy": policy}

        return newRule

    def add_dns_policy(self, tokens, scope):
        if len(tokens) < 6:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        domain = tokens[2].replace("'", "")
        if domain == tokens[2]:
            domain = self.getContextVar(domain, scope)
        rule_type = tokens[5].replace("'", "")
        if rule_type == tokens[5]:
            rule_type = self.getContextVar(rule_type, scope)

        try:
            logger.info(tokens[0] + " " + tokens[1] + " " + f"{domain}" + " " + tokens[3] + " " + tokens[
                4] + " " + f"{rule_type}")
            self.service_graph_instance.add_dns_policy(domain, rule_type)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def shutdown(self, tokens, scope):
        # shutdown 'host1' # can be also a list of nodes
        if len(tokens) < 2:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        node = tokens[1].replace("'", "")
        if node == tokens[1]:
            node = self.getContextVar(node, scope)

        try:
            logger.info(tokens[0] + " " + f"{node}")
            self.service_graph_instance.shutdown(node)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def isolate(self, tokens, scope):
        # isolate 'host1' # can be also a list of nodes
        if len(tokens) < 2:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        node = tokens[1].replace("'", "")
        if node == tokens[1]:
            node = self.getContextVar(node, scope)

        try:
            logger.info(tokens[0] + " " + f"{node}")
            self.service_graph_instance.isolate(node)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def add_honeypot(self, tokens, scope):
        # add_honeypot with 'apache_vulnerability' # can be also a list of vulnerabilities
        if len(tokens) < 3:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        vulnerability = tokens[2].replace("'", "")
        if vulnerability == tokens[2]:
            vulnerability = self.getContextVar(vulnerability, scope)

        try:
            logger.info(tokens[0] + " " + tokens[1] + " " + f"{vulnerability}")
            new_node = self.service_graph_instance.add_honeypot(vulnerability)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def add_network_monitor(self, tokens, scope):
        # add_network_monitor behind 'host1' in path # path is a list of nodes, and in it 'host1' must be present
        if len(tokens) < 5:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        node = tokens[2].replace("'", "")
        if node == tokens[2]:
            node = self.getContextVar(node, scope)
        path = tokens[4].replace("'", "")
        if path == tokens[4]:
            path = self.getContextVar(path, scope)

        try:
            logger.info(tokens[0] + " " + tokens[1] + " " + f"{node}" + " " + tokens[3] + " " + f"{path}")
            new_node = self.service_graph_instance.add_network_monitor(node, path)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def move(self, tokens, scope):
        # move iteration_element to reconfiguration_net
        if len(tokens) < 4:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        node = tokens[1].replace("'", "")
        if node == tokens[1]:
            node = self.getContextVar(node, scope)
        net = tokens[3].replace("'", "")
        if net == tokens[3]:
            net = self.getContextVar(net, scope)

        try:
            logger.info(tokens[0] + " " + f"{node}" + " " + tokens[2] + " " + f"{net}")
            self.service_graph_instance.move(node, net)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def execute(self, tokens, scope):
        # executes the function in the system environment
        if len(tokens) < 2:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")
        functionName = tokens[1].replace("'", "")
        if functionName == tokens[1]:
            functionName = self.getContextVar(functionName, scope)

        try:
            logger.info(tokens[0] + " " + f"{functionName}")
            function = custom_functions.FunctionMappings[functionName]
            if len(tokens) > 3:
                function(self.global_scope[tokens[2]], self.global_scope[tokens[3]])
            elif len(tokens) > 2:
                function(self.global_scope[tokens[2]])
            else:
                function()
        except Exception as ex:
            raise ex  # just rethrow it for now

    def getContextVar(self, key, scope):
        # gets the value of the given variable found searching starting from the innermost scope
        if key in scope:
            return scope[key]
        if "outerScope" in scope:
            return self.getContextVar(key, scope["outerScope"])
        raise Exception(f"Can't find this variable in the program stack: {key}")

    def setContextVar(self, key, scope, new_value):
        # sets the value of the given variable found searching starting from the innermost scope
        if key in scope:
            scope[key] = new_value
            return new_value
        if "outerScope" in scope:
            return self.setContextVar(key, scope["outerScope"], new_value)
        raise Exception(f"Can't find this variable in the program stack: {key}")

    def evaluateRow(self, riga: str, scope, sentences):
        # this function is called on each row of the "program" and for each one executes
        # the relative construct "if/iterate_on" or calls the given function

        # recipe comment line
        if riga.startswith('#'):
            return 0

        # tokens = nltk.word_tokenize(riga) # this splits also on '
        tokens = riga.split(" ")

        match tokens[0]:
            case "list_paths":
                # sets the variable path_list in the scope. path_list will contain a list of paths
                logger.info("Now calling list_paths function ...")
                self.list_paths(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "find_node":
                # sets found_node to the name of the first node found on the path, if one is not found set to None
                # sets found to true or false
                logger.info("Now calling find_node function ...")
                self.find_node(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "add_node":
                # adds a node of the specified type between two nodes
                # sets the new_node variable on the scope
                logger.info("Now calling add_node function ...")
                self.add_node(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "add_firewall":
                # takes a node name and a path as input
                # puts a firewall right behind the node on that path
                # example giving as input node2 and the following path as a list in the same order as displayed:
                # node1 <---> node2 <---> node3 <---> node4
                # node1 <---> node2 <---> firewall <---> node3 <---> node4
                logger.info("Now calling add_firewall function ...")
                self.add_firewall(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "add_honeypot":
                # adds a new host with the given vulnerability in the honey net
                logger.info("Now calling add_honeypot function ...")
                self.add_honeypot(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "add_network_monitor":
                # takes a node name and a path as input
                # puts a network monitor node right behind the node on that path
                # example giving as input node2 and the following path as a list in the same order as displayed:
                # node1 <---> node2 <---> node3 <---> node4
                # node1 <---> node2 <---> netowork_monitor <---> node3 <---> node4
                logger.info("Now calling add_network_monitor function ...")
                self.add_network_monitor(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "move":
                logger.info("Now calling move function ...")
                self.move(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "shutdown":
                # takes a node name as input and shuts it down
                logger.info("Now calling shutdown function ...")
                self.shutdown(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "isolate":
                # takes a node name as input and disconnect all interfaces
                logger.info("Now calling isolate function ...")
                self.isolate(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "add_filtering_rules":
                # adds the rule to the rule list of the specified firewall node
                # doesn't set anything on the scope
                logger.info("Now calling add_filtering_rules function ...")
                self.add_filtering_rules(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "add_dns_policy":
                # adds the rule to the rule list of the network dns_server node
                # doesn't set anything on the scope
                logger.info("Now calling add_dns_policy function ...")
                self.add_dns_policy(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "execute":
                # executes the function with the name passed as argument
                logger.info("Now calling execute function ...")
                self.execute(tokens, scope)
                scope["rowCursor"] += 1
                return 0
            case "iterate_on":  # "nested iterate" works
                logger.info("Now going into iterate_on construct ...")
                iterateScope = {
                    "some_variable_for_iterate_scope": 0,
                    "outerScope": scope
                }
                scope["blockStartCursor"] = self.getContextVar("rowCursor", scope) + 1
                nameOfListToIterateOn = tokens[1]
                for item in self.getContextVar(nameOfListToIterateOn, scope):
                    iterateScope["iteration_element"] = item
                    iterateScope["rowCursor"] = scope["blockStartCursor"]
                    self.interpret(statements=sentences, length=len(sentences), scope=iterateScope)
                    scope["rowCursor"] = iterateScope["rowCursor"]
                return 0
            case "if":  # "nested if else" not tested but should work
                logger.info("Now going into if/else construct ...")
                ifScope = {
                    "some_variable_for_if_scope": 0,
                    "outerScope": scope,
                    "rowCursor": self.getContextVar("rowCursor", scope)
                }
                # compute "if" condition, considering potential "not" keyword
                condition = (not self.getContextVar(tokens[2], scope)) if tokens[1] == "not" else self.getContextVar(
                    tokens[1], scope)

                if condition:
                    # condition true -> take if branch execute normally with interpret. when encountering else or
                    # endif will return here and set outer rowCursor to after the endif
                    ifScope["rowCursor"] = self.getContextVar("rowCursor", scope) + 1
                    self.interpret(statements=sentences, length=len(sentences), scope=ifScope)
                    for index, item in enumerate(sentences[ifScope["rowCursor"] - 1:], start=ifScope["rowCursor"] - 1):
                        if item == "endif":
                            scope["rowCursor"] = index + 1
                            break
                    return 0
                else:
                    # condition false -> take else branch jump to after else (set rowcursor) or endif and continue
                    # normally with interpret, then when ecnountering endif will return here and set outer rowCursor
                    # to after the endif
                    for index, item in enumerate(sentences[ifScope["rowCursor"]:], start=ifScope["rowCursor"]):
                        if item == "else":
                            ifScope["rowCursor"] = index + 1
                            self.interpret(statements=sentences, length=len(sentences), scope=ifScope)
                            for index2, item2 in enumerate(sentences[ifScope["rowCursor"]:], start=ifScope["rowCursor"]):
                                if item2 == "endif":
                                    scope["rowCursor"] = index2 + 1
                                    return 0
                        if item == "endif":
                            scope["rowCursor"] = index + 1
                            return 0
            case "enditeration":  # end of iteration loop -> return to calling interpreter
                logger.info("Exiting iteration construct")
                scope["rowCursor"] += 1
                return 1
            case "endif":  # end of if block -> return to calling interpreter
                logger.info("Exiting if/else construct")
                scope["rowCursor"] += 1
                return 1
            case "else":  # end of if branch -> return to calling interpreter
                logger.info("Now exiting if/else construct")
                scope["rowCursor"] += 1
                return 1
            case "testIf":  # just print testIf
                logger.info("testIf executed")
                scope["rowCursor"] += 1
                return 0
            case "testElse":  # just print testElse
                logger.info("testElse executed")
                scope["rowCursor"] += 1
                return 0
            case "invertCondizioneTest":
                if self.getContextVar("condizioneTest", scope):
                    self.setContextVar("condizioneTest", scope, False)
                else:
                    self.setContextVar("condizioneTest", scope, True)
                logger.info("invertCondizioneTest executed")
                logger.info(scope["iteration_element"])
                scope["rowCursor"] += 1
                return 0
            case "actionThatDoesNothing":
                logger.info("actionThatDoesNothing executed")
                logger.info(scope["iteration_element"])
                scope["rowCursor"] += 1
                return 0
            case _:
                logger.error(f"Unrecognized statement: {tokens[0]}")
                raise Exception(f"Unrecognized statement: {tokens[0]}")

    def interpret(self, statements, length, scope):
        # This is the interpreter, that loops on the program rows and calls the evaluateRow for evaluating them
        # It can be recursevely called from language constructs, for example an iteration statement calls it on
        # each loop, and once the iteration block is completely executed control is returned to the outer
        # interpreter (see break call inside the {if result == 1} ).
        # interpret() is called recursively when encountering a block construct ie (while, if).

        # Shows starting state of the landscape
        self.service_graph_instance.plot()

        logger.info("Starting interpreter parsing ...")
        while self.getContextVar("rowCursor", scope) < length:
            result = self.evaluateRow(statements[self.getContextVar("rowCursor", scope)], scope, statements)
            if result == 1:  # for ending iteration and if blocks
                break

    def remediate(self, recipe_to_run):

        # if self.recipeToRun is None:
        #     raise Exception("Recipe has not been set")

        self.recipeToRun = recipe_to_run

        # make recipe string readable by the interpreter
        rawSentences = nltk.line_tokenize(self.recipeToRun)
        logger.info("Tokenized per line")
        sentences = []
        for sentence in rawSentences:
            sentences.append(sentence.strip())  # remove trailing and leading extra white spaces
        logger.info("Removed trailing and leading whitespaces")

        # the call to interpret() will run the interpreter with te selected recipe
        logger.info("Launching interpreter ...")
        self.global_scope["rowCursor"] = 0
        self.interpret(statements=sentences, length=len(sentences), scope=self.global_scope)
        # self.getSTIXReport()
        # self.getCACAORemediationPlaybook()
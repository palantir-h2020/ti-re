import json
import logging
import nltk
import yaml
from cacao_classes import Command, EndStep, IfConditionStep, Playbook, SingleActionStep, StartStep, Step, WhileConditionStep

logging.basicConfig(level=logging.DEBUG)

class Recipe():

    def __init__(self, text: str) -> None:
        self.text: str = text
        self.workflow: list[Step] = []
        self.GlobalScope: dict = {
            "rowCursor": 0,
            "testList": ["d1", "d2", "d3"],
            "testList2": ["e1", "e2"],
            "previousStep": StartStep()
        }
        self.workflow.append(self.GlobalScope["previousStep"])

    def updateWorkflowSequence(self, scope, new_step):
        previousStep: Step = self.getContextVar("previousStep", scope)
        if isinstance(previousStep, WhileConditionStep):
            if previousStep["on_true"] is None:
                # case where the on_true step_id has NOT been already set. This happens when the interpreter is parsing
                # the first line after the iterate_on
                previousStep.setOnTrueStep([new_step.step_id])
            else:
                # case where the on_true step_id has been already set. This happens after the interpreter has exited the iterate_on block
                # and is now parsing the first line after the endinteration.
                previousStep.setOnFalseStep([new_step.step_id])
        elif isinstance(previousStep, IfConditionStep):
            if previousStep["on_true"] is None:
                previousStep.setOnTrueStep([new_step.step_id])
            elif previousStep["on_false"] is None and scope.get("hasElseBranch") is True:
                previousStep.setOnFalseStep([new_step.step_id])
            else:
                previousStep.setOnCompletionStep([new_step.step_id])
        else:
            previousStep.setOnCompletionStep(new_step.step_id)
        scope["previousStep"] = new_step
        self.workflow.append(new_step)

    def getContextVar(self, key, scope):
        # gets the value of the given variable found searching starting from the innermost scope
        if key in scope:
            return scope[key]
        if "outerScope" in scope:
            return self.getContextVar(key, scope["outerScope"])
        raise Exception(f"Can't find this variable in the program stack: {key}")

    def setContextVar(self, key, scope, newValue):
        # sets the value of the given variable found searching starting from the innermost scope
        if key in scope:
            scope[key] = newValue
            return newValue
        if "outerScope" in scope:
            return self.setContextVar(key, scope["outerScope"], newValue)
        raise Exception(f"Can't find this variable in the program stack: {key}")

    def list_paths(self, tokens, scope):
        if len(tokens) < 5:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")


        source = tokens[2].replace("'", "")
        if source == tokens[2]:
            source = f"$${source}$$"
        destination = tokens[4].replace("'", "")
        if destination == tokens[4]:
            destination = f"$${destination}$$"

        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + tokens[1] + " " + f"{source}" + " " + tokens[3] + " " + f"{destination}")
        step.addCommands(command)
        step.addOutArg("$$path_list$$")

    def find_node(self, tokens, scope):
        if len(tokens) < 6:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        nodeType = tokens[3].replace("'", "")  # node type to search for
        if nodeType == tokens[3]:
            nodeType = f"$${nodeType}$$"
        path = tokens[5].replace("'", "")  # where to search in for the node
        if path == tokens[5]:
            path = f"$${path}$$"

        # Support for additional "capability" argument
        if len(tokens) == 8:
            capability = tokens[7].replace("'", "")
            if capability == tokens[7]:
                capability = f"$${capability}$$"
            capabilities = [capability]  # for now supports only one capability as input
        else:
            capabilities = []

        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + f"{nodeType}" + " " + tokens[4] + " " + f"{path}")
        step.addCommands(command)
        step.addOutArg("$$path_list$$", "$$found$$")

    def add_node(self, tokens, scope):
        if len(tokens) < 8:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        nodeType = tokens[3].replace("'", "")
        if nodeType == tokens[3]:
            nodeType = f"$${nodeType}$$"
        node1 = tokens[5].replace("'", "")
        if node1 == tokens[3]:
            node1 = f"$${node1}$$"
        node2 = tokens[7].replace("'", "")
        if node2 == tokens[3]:
            node2 = f"$${node2}$$"


        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + f"{nodeType}" + " " + tokens[4]+ " " + f"{node1}" + " " + tokens[6] + " " + f"{node2}")
        step.addCommands(command)
        step.addOutArg("$$new_node$$")

    def add_firewall(self, tokens, scope):
        if len(tokens) < 5:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        node = tokens[2].replace("'", "")
        if node == tokens[2]:
            node = f"$${node}$$"
        path = tokens[4].replace("'", "")
        if path == tokens[4]:
            path = f"$${path}$$"

        # Support for additional "capability" argument
        if len(tokens) == 7:
            capability = tokens[6].replace("'", "")
            if capability == tokens[6]:
                capability = f"$${capability}$$"
            capabilities = [capability]  # for now supports only one capability as input
        else:
            capabilities = ["level_4_filtering", "level_7_filtering"]

        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + tokens[1] + " " + f"{node}" + " " + tokens[3] + " " + f"{path}" + " " + tokens[5])
        step.addCommands(command)
        step.addOutArg("$$new_node$$")

    def add_filtering_rules(self, tokens, scope):
        if len(tokens) < 4:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        node = tokens[3].replace("'", "")
        if node == tokens[3]:
            node = f"$${node}$$"
        rules = tokens[1].replace("'", "")
        if rules == tokens[1]:
            rules = f"$${rules}$$"

        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0]+ " " + "rules" + " " + tokens[2] + " " + f"{node}")
        step.addCommands(command)

    def shutdown(self, tokens, scope):
        # shutdown 'host1' # can be also a list of nodes
        if len(tokens) < 2:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        node = tokens[1].replace("'", "")
        if node == tokens[1]:
            node = f"$${node}$$"

        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + f"{node}")
        step.addCommands(command)

    def isolate(self, tokens, scope):
        # isolate 'host1' # can be also a list of nodes
        if len(tokens) < 2:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        node = tokens[1].replace("'", "")
        if node == tokens[1]:
            node = f"$${node}$$"

        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + f"{node}")
        step.addCommands(command)

    def add_honeypot(self, tokens, scope):
        # add_honeypot with 'apache_vulnerability' # can be also a list of vulnerabilities
        if len(tokens) < 3:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        vulnerability = tokens[2].replace("'", "")
        if vulnerability == tokens[2]:
            vulnerability = f"$${vulnerability}$$"

        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + tokens[1] + " " + f"{vulnerability}")
        step.addCommands(command)
        step.addOutArg("$$new_node$$")

    def add_network_monitor(self, tokens, scope):
        # add_network_monitor behind 'host1' in path # path is a list of nodes, and in it 'host1' must be present
        if len(tokens) < 5:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        node = tokens[2].replace("'", "")
        if node == tokens[2]:
            node = f"$${node}$$"
        path = tokens[4].replace("'", "")
        if path == tokens[4]:
            path = f"$${path}$$"


        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + tokens[1] + " " + f"{node}" + " " + tokens[3] + " " + f"{path}")
        step.addCommands(command)
        step.addOutArg("$$new_node$$")

    def move(self, tokens, scope):
        # move iteration_element to reconfiguration_net
        if len(tokens) < 4:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        node = tokens[1].replace("'", "")
        if node == tokens[1]:
            node = f"$${node}$$"
        net = tokens[3].replace("'", "")
        if net == tokens[3]:
            net = f"$${net}$$"


        step = SingleActionStep()
        self.updateWorkflowSequence(scope, step)
        command = Command(type="manual", command=tokens[0] + " " + f"{node}" + " " + tokens[2] + " " + f"{net}")
        step.addCommands(command)
        step.addOutArg("$$new_node$$")

    def evaluateRow(self, riga, scope, statements) -> int:
        tokens = riga.split(" ")

        if tokens[0] == "iterate_on":
            logging.info("Now going into iterate_on function ...")
            step = WhileConditionStep(tokens[1])
            extensionForIterationOnList = {
                "type_of_while": "iterate_on",
                "info": "Interpreter will treat this while as a for each statement",
                "iterate_on": f"$${tokens[1]}$$"
            }

            step.addExtension(self.GlobalScope["iterateOnExtensionId"], extensionForIterationOnList)
            self.updateWorkflowSequence(scope, step)


            step.addVariable("iterationIndex", 0)
            condition = f"$$iterationIndex$$ < $${tokens[1]}.length$$"
            step.setCondition(condition)
            #todo add extension to while step like out_args that outputs (ie: saves the variable
            #todo into step_variables) the variable iterationElement at each step

            iterateScope = {
                "outerScope": scope,
                "rowCursor": scope["rowCursor"] + 1
            }

            self.interpet(statements=statements, lenght=len(statements), scope=iterateScope)
            scope["rowCursor"] = iterateScope["rowCursor"]

            return 0
        elif tokens[0] == "if":
            logging.info("Now going into if/else construct ...")
            step = IfConditionStep(tokens[1])
            self.updateWorkflowSequence(scope, step)

            condition = f"$${tokens[2]}$$:value = true" if tokens[1] == "not" else f"$${tokens[1]}$$:value = false"
            step.setCondition(condition)

            #todo create STIX 2 Pattern object

            ifScope = {
                "outerScope": scope,
                "rowCursor": scope["rowCursor"] + 1
            }

            returnCode = self.interpet(statements=statements, lenght=len(statements), scope=ifScope)
            scope["rowCursor"] = ifScope["rowCursor"]

            if returnCode == 3:
                elseScope = {
                    "outerScope": scope,
                    "rowCursor": scope["rowCursor"],
                    "hasElseBranch": True
                }
                self.interpet(statements=statements, lenght=len(statements), scope=elseScope)
                scope["rowCursor"] = elseScope["rowCursor"]

            return 0
        elif tokens[0] == "end_iteration":
            logging.info("Exiting iteration construct")
            scope["rowCursor"] += 1
            return 1
        elif tokens[0] == "endif":
            logging.info("Exiting if/else construct")
            scope["rowCursor"] += 1
            return 2
        elif tokens[0] == "else":
            logging.info("Now exiting if/else construct")
            scope["rowCursor"] += 1
            return 3
        elif tokens[0] == "list_paths":
            logging.info("Now calling list_paths function ...")
            self.list_paths(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "find_node":
            logging.info("Now calling find_node function ...")
            self.find_node(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_node":
            logging.info("Now calling add_node function ...")
            self.add_node(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_firewall":
            logging.info("Now calling add_firewall function ...")
            self.add_firewall(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_honeypot":
            logging.info("Now calling add_honeypot function ...")
            self.add_honeypot(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_network_monitor":
            logging.info("Now calling add_network_monitor function ...")
            self.add_network_monitor(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "move":
            logging.info("Now calling move function ...")
            self.move(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "shutdown":
            logging.info("Now calling shutdown function ...")
            self.shutdown(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "isolate":
            logging.info("Now calling isolate function ...")
            self.isolate(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_filtering_rules":
            logging.info("Now calling add_filtering_rules function ...")
            self.add_filtering_rules(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        else:
            command = Command(type="manual", command=" ".join(tokens))
            step = SingleActionStep(command)
            self.updateWorkflowSequence(scope, step)
            scope["rowCursor"] += 1
            #print(f"{tokens}")
            return 0


    def interpet(self, statements, lenght, scope):
        while (scope["rowCursor"] < lenght):
            result = self.evaluateRow(statements[scope["rowCursor"]], scope, statements)
            if result != 0:  # for ending iteration and if blocks
                return result

    def toCACAOPlaybook(self) -> Playbook:

        playbook = Playbook(playbook_type="playbook",
                            name="playbookName",
                            playbook_types=["remediation"])

        self.GlobalScope["iterateOnExtensionId"] = playbook.addExtensionDefinition(name="iterate_on extension")
        self.GlobalScope["rowCursor"] = 0



        rawSentences = nltk.line_tokenize(self.text)
        sentences = []
        for sentence in rawSentences:
            sentences.append(sentence.strip())  # remove trailing and leading extra white spaces
        self.interpet(statements=sentences, lenght=len(sentences), scope=self.GlobalScope)
        step = EndStep()
        self.updateWorkflowSequence(self.GlobalScope, step)

        playbook.addSteps(*self.workflow)

        return playbook


if __name__ == "__main__":

    interpreterTest1 = "iterate_on testList\n\
                    iterate_on testList2\n\
                        add_dns_policy for iteration_element of type 'block_all_queries'\n\
                        prova prova prova3\n\
                    enditeration\n\
                    fuori while\n\
                enditeration\n\
                proprioEnd"

    interpreterTest2 = "list_paths from impacted_host_ip to 'attacker'                                           \n\
                    iterate_on path_list                                                                     \n\
                        find_node of type 'network_monitor' in iteration_element                             \n\
                        if not found                                                                         \n\
                            add_network_monitor behind impacted_host_ip in iteration_element                 \n\
                        endif                                                                                \n\
                    enditeration\n\
                    dopoteration"

    interpreterTest3 = "iterate_on listTest1\n                                       \
            invertCondizioneTest other optional keywords and parameters\n            \
            iterate_on listTest2\n                                                   \
                actionThatDoesNothing other optional keywords and parameters\n       \
                if condizioneTest\n                                                  \
                    testIf other optional keywords and parameters\n                  \
                else\n                                                               \
                    testElse other optional keywords and parameters\n                \
                endif\n                                                              \
            enditeration\n                                                           \
        enditeration"

    interpreterTest4= "iterate_on listTest1\n\
                            iterate_on listTest2\n\
                                iterate_on listTest3\n\
                                        if condizioneTest\n                                                  \
                                            if condizioneTestIf\n                                                  \
                                                testIf2 other optional keywords and parameters\n                  \
                                            else\n                                                               \
                                                testElse2 other optional keywords and parameters\n                \
                                            endif\n \
                                            provafineif\n\
                                        else\n                                                               \
                                            if not condizioneTestElse\n                                                  \
                                                testIf3 other optional keywords and parameters\n                  \
                                            endif\n \
                                        endif\n \
                                    enditeration \n\
                            enditeration \n\
                        enditeration"


    filter_payload_recipe ="list_paths from impacted_host_ip to 'attacker'                                             \n\
                        iterate_on path_list                                                                       \n\
                            find_node of type 'firewall' in iteration_element with 'level_7_filtering'             \n\
                            if not found                                                                           \n\
                                add_firewall behind impacted_host_ip in iteration_element with 'level_7_filtering' \n\
                                add_filtering_rules rules_level_7 to new_node                                      \n\
                            else                                                                                   \n\
                                add_filtering_rules rules_level_7 to found_node                                    \n\
                            endif                                                                                  \n\
                        enditeration"

    filter_ip_port_recipe = "list_paths from impacted_host_ip to 'attacker'                                            \n\
                            iterate_on path_list                                                                       \n\
                                find_node of type 'firewalll' in iteration_element with 'level_4_filtering'             \n\
                                if not found                                                                           \n\
                                    add_firewall behind impacted_host_ip in iteration_element with 'level_4_filtering' \n\
                                    add_filtering_rules rules_level_4 to new_node                                      \n\
                                else                                                                                   \n\
                                    add_filtering_rules rules_level_4 to found_node                                    \n\
                                endif                                                                                  \n\
                            enditeration"

    redirect_domains_recipe = "iterate_on domains                                                                      \n\
                                add_dns_policy for iteration_element of type 'block_all_queries'                       \n\
                            enditeration"

    monitor_traffic_recipe = "list_paths from impacted_host_ip to 'attacker'                                           \n\
                            iterate_on path_list                                                                       \n\
                                find_node of type 'network_monitor' in iteration_element                               \n\
                                if not found                                                                           \n\
                                    add_network_monitor behind impacted_host_ip in iteration_element                   \n\
                                endif                                                                                  \n\
                            enditeration"

    put_into_reconfiguration_recipe = "iterate_on impacted_nodes                                                       \n\
                                            move iteration_element to 'reconfiguration_net'                            \n\
                                        enditeration"

    add_honeypot_recipe = "iterate_on impacted_nodes                                                                   \n\
                                add_honeypot with 'apache_vulnerability'                                               \n\
                            enditeration"

    shutdown_recipe = "iterate_on impacted_nodes                                                                       \n\
                            shutdown iteration_element                                                                 \n\
                        enditeration"

    isolate_recipe = "iterate_on impacted_nodes                                                                        \n\
                        isolate iteration_element                                                                      \n\
                    enditeration"

    ricetta = Recipe(isolate_recipe)

    with open('cacaoPlaybook.json', 'w', encoding='utf8') as outfile:
        json.dump(ricetta.toCACAOPlaybook().toDict(), outfile, indent=4)

    print(yaml.dump(ricetta.toCACAOPlaybook().toDict(), default_flow_style=False, sort_keys=False))
    # for el in ricetta.toCACAOPlaybook():
    #     print(el)





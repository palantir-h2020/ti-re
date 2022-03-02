import copy
import logging
import nltk
import sys
import json
import serviceGraph
import SecurityControlFunctions
import EnvironmentFunctions

logging.basicConfig(level=logging.DEBUG)

filter_payload_recipe_old = "list_paths from 'host1' to 'attacker'\n                                               \
     iterate_on path_list\n                                                                                        \
         find_node of type 'filtering_node'\n                                                                      \
         if not found:\n                                                                                           \
             add_node of type 'filtering_node' between impacted_node and threat_source\n                           \
             add_rule attack_payload to new_node payload filtering list\n                                          \
         else\n                                                                                                    \
             add_rule attack_payload to filtering_node payload filtering list\n                                    \
         endif\n                                                                                                   \
     enditeration"

# recipe for nested "iterate" and "if" constructs testing.
interpreterTest1 = "iterate_on listTest1\n                                                                         \
         invertCondizioneTest other optional keywords and parameters\n                                             \
         iterate_on listTest2\n                                                                                    \
             actionThatDoesNothing other optional keywords and parameters\n                                        \
             if condizioneTest\n                                                                                   \
                 testIf other optional keywords and parameters\n                                                   \
             else\n                                                                                                \
                 testElse other optional keywords and parameters\n                                                 \
             endif\n                                                                                               \
         enditeration\n                                                                                            \
     enditeration"

filter_payload_recipe = "list_paths from impacted_host_ip to 'attacker'                                             \n\
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
                            find_node of type 'firewall' in iteration_element with 'level_4_filtering'             \n\
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

fbm_recipe = " execute 'fbm_function' UnauthorizedAccessAlert"


class Remediator():

    def __init__(self, SecurityControlRepository=None, ThreatRepository=None, recipeToRun=None,
                 GlobalScope=None) -> None:
        logging.info("Initializing security controls repository")
        if SecurityControlRepository is None:
            self.SecurityControlRepository = {}
        else:
            self.SecurityControlRepository = copy.deepcopy(SecurityControlRepository)

        logging.info("Initializing threat repository")
        if ThreatRepository is None:
            self.ThreatRepository = copy.deepcopy(ThreatRepository)
        else:
            self.ThreatRepository = ThreatRepository
        self.recipeToRun = recipeToRun

        logging.info("Initializing service graph")
        self.ServiceGraph = serviceGraph.ServiceGraph()

        logging.info("Initializing global scope")
        if GlobalScope is None:
            self.GlobalScope = {
                # "listTest1": [1, 2, 3],
                # "listTest2": ["a", "b", "c"],
                # "condizioneTest": False,
                # "varProva1": 10,
                # "varProva2": "prova",
                # "path_list": None,
                "rowCursor": 0,
                # "impacted_nodes": ["10.1.0.10", "10.1.0.11"], # integrity information, if any
                # "vulnerable_nodes": [],  # nodes vulnerable to the threat, if any
                # "services_involved": [],
            }

        logging.info("Initializing recipe repository")
        self.RecipeRepository = {
            "filter_payload_recipe": {
                "description": "Filter payload on impacted node",
                "requiredCapabilities": ["level_7_filtering"],
                "value": filter_payload_recipe
            },
            "filter_ip_port_recipe": {
                "description": "Filter ip and port on impacted node",
                "requiredCapabilities": ["level_4_filtering"],
                "value": filter_ip_port_recipe
            },
            "redirect_domains_recipe": {
                "description": "Add rule to DNS server for redirection of malicious DNS domains queries to safe one",
                "requiredCapabilities": ["dns_policy_manager"],
                "value": redirect_domains_recipe
            },
            "monitor_traffic_recipe": {
                "description": "Monitor traffic on impacted node",
                "requiredCapabilities": ["traffic_monitor"],
                "value": monitor_traffic_recipe
            },
            "put_into_reconfiguration_recipe": {
                "description": "Put impacted nodes into reconfiguration net",
                "requiredCapabilities": [],
                "value": put_into_reconfiguration_recipe
            },
            "add_honeypot_recipe": {
                "description": "Add honeypot for each impacted node",
                "requiredCapabilities": [],
                "value": add_honeypot_recipe
            },
            "shutdown_recipe": {
                "description": "Shutdown impacted nodes",
                "requiredCapabilities": [],
                "value": shutdown_recipe
            },
            "isolate_recipe": {
                "description": "Isolate impacted nodes",
                "requiredCapabilities": [],
                "value": isolate_recipe
            },
            "fbm_recipe": {
                "description": "Call the fbm_function",
                "requiredCapabilities": [],
                "value": fbm_recipe
            },

        }

        self.CapabilityToSecurityControlMappings = {
            "level_4_filtering": "iptables",
            "level_7_filtering": "generic_level_7_filter",
            "level_4_monitor": "generic_network_traffic_monitor"
        }

    def setCapabilitiesToSecurityControlMappings(self, requiredCapabilities: list):
        """Sets the CapabilityToSecurityControlMappings dictionary according to the capabilities needed for
        the execution of the selected recipe. Each capability is mapped to the respective security control
        that will be used to enforce that capability.
        Returns nothing"""

        for el in requiredCapabilities:
            for key, value in self.SecurityControlRepository.items():
                if el in value["capabilities"]:
                    self.CapabilityToSecurityControlMappings[el] = key
                    break

    def generateRule(self, capability, policy):
        """Generates a rule for policy enforcement in the language specific of that security control with
        which the policy will be enforced. It taps into the SecurityControlToFunctionMappings dictionary in
        which each SecurityControl is mapped to a command generator function.
        Returns a dictionary representing the rule.
        """

        securityControlName = self.CapabilityToSecurityControlMappings[capability]
        ruleGenerator = SecurityControlFunctions.FunctionMappings[
            securityControlName]  # this is a callable object, i.e. a function object

        if capability == "level_4_filtering":
            generatedRule = ruleGenerator(policy)
        else:
            generatedRule = ruleGenerator(policy)

        newRule = {"type": capability,
                   "enforcingSecurityControl": securityControlName,
                   "rule": generatedRule}

        return newRule

    def selectBestRecipe(self, threatName, threatLabel):
        """Selects the best recipe enforceable for the given threat taking into account the recipes priority. If
        a given recipe requires a capability not enforceable with any security control available in the
        SecurityControlsRepository it will return the next one in line that can be enforced.
        Returns the name of the selected recipe."""

        maxPriority = 0
        bestRecipeName = None
        recipesForThreat = None
        try:
            recipesForThreat = self.ThreatRepository[threatName][threatLabel]["recipes"]
        except KeyError:
            recipesForThreat = self.ThreatRepository[threatName]["unknown"]["recipes"]
        for el in recipesForThreat:
            if el["priority"] > maxPriority and self.checkEnforceability(el["recipeName"]):
                maxPriority = el["priority"]
                bestRecipeName = el["recipeName"]

        return bestRecipeName

    def checkEnforceability(self, recipeName):
        """Checks the enforceability of a given recipe, that is, for every required capability a SecurityControl
        capable of enforcing it is available in the SecuityControlRepository"""

        # Get the set of required capabilities from the RecipeRepository
        requiredCapabilities = set(self.RecipeRepository[recipeName]["requiredCapabilities"])

        # Get the set of enforceable capabilities from the SecurityControlRepository
        enforceableCapabilities = set()
        for el in self.SecurityControlRepository.values():
            enforceableCapabilities.update(el["capabilities"])

        if requiredCapabilities.issubset(enforceableCapabilities):
            return True
        else:
            return False

    def prepareDataForRemediationOfMalware(self, threatType, threatName, impacted_host_ip, attacker_port, attacker_ip):

        self.GlobalScope["threat_type"] = threatType  # malware
        self.GlobalScope["threat_name"] = threatName  # command_control / Cridex / Zeus
        self.GlobalScope["impacted_host_ip"] = impacted_host_ip  # 10.1.0.10
        self.GlobalScope["c2serversPort"] = attacker_port  # 22
        self.GlobalScope["attacker_ip"] = attacker_ip  # 12.12.12.12

        if threatName == "command_control":
            logging.info("Generic command and control threat detected, apply countermeasures ...")
            self.GlobalScope["rules_level_4"] = [
                {"level": 4, "victimIP": impacted_host_ip, "c2serversPort": attacker_port, "c2serversIP": attacker_ip,
                 "proto": "TCP"}]

            suggestedRecipe = self.ThreatRepository[threatType][threatName]["suggestedRecipe"]
            logging.info(
                f"Recommended recipe for the threat: \n{self.RecipeRepository[suggestedRecipe]['description']} with parameters: ")
            logging.info(
                f"Impacted host ip: {impacted_host_ip} \nAttacker port: {attacker_port} \nAttacker ip: {attacker_ip}")
        elif threatName in self.ThreatRepository[threatType]:
            logging.info("Threat found in the repository, applying specific countermeasures ...")
            mitigation_rules = self.ThreatRepository[threatType][threatName]["rules"]
            self.GlobalScope["rules_level_7"] = [rule for rule in mitigation_rules if
                                                 rule.get("level") == 7 and rule.get(
                                                     "proto") != "DNS"]  # DNS rules are managed below
            self.GlobalScope["rules_level_4"] = [rule for rule in mitigation_rules if rule.get("level") == 4]

            # complete ThreatRepository data with fresh information regarding port and victim host received as alert
            for rule in self.GlobalScope["rules_level_4"]:
                rule["victimIP"] = impacted_host_ip
                rule["c2serversPort"] = attacker_port

            # add a blocking rule if the attacker ip present in the alert isn't already in the ThreatRepository
            threatRepositoryAttackers = [rule["c2serversIP"] for rule in mitigation_rules if rule.get("level") == 4]
            if attacker_ip not in threatRepositoryAttackers:
                self.GlobalScope["rules_level_4"].append({"level": 4, "victimIP": impacted_host_ip,
                                                          "c2serversPort": attacker_port,
                                                          "c2serversIP": attacker_ip,
                                                          "proto": "TCP"})

            # if the threat repository doesn't contain specific level_4_filtering rules
            # for this specific malware then generate them from the information gathered from the CLI
            if (len(self.GlobalScope["rules_level_4"]) == 0):
                self.GlobalScope["rules_level_4"] = [{"level": 4, "victimIP": impacted_host_ip,
                                                      "c2serversPort": attacker_port,
                                                      "c2serversIP": attacker_ip,
                                                      "proto": "TCP"}]

            # get dns rules
            self.GlobalScope["domains"] = [rule["domain"] for rule in mitigation_rules if rule.get("proto") == "DNS"]

            # set impacted_nodes variable, that is used in the other recipes
            self.GlobalScope["impacted_nodes"] = [impacted_host_ip]

            # from here on is just logging
            suggestedRecipe = self.ThreatRepository[threatType][threatName]["suggestedRecipe"]
            logging.info(
                f"Recommended recipe for the threat: ( {self.RecipeRepository[suggestedRecipe]['description']} )\nWith parameters: ")
            logging.info(
                f"Impacted host ip: {impacted_host_ip} \nImpacted host port: {attacker_port} \nAttacker ip: {attacker_ip}")

            for rule in self.GlobalScope["rules_level_7"]:
                payload = rule["payload"]
                logging.info(f"Payload: {payload}")
        else:
            logging.info("Threat not found in the repository, applying generic countermeasures ...")
            self.GlobalScope["impacted_nodes"] = [impacted_host_ip]
            suggestedRecipe = "isolate_recipe"
            logging.info(
                f"Recommended recipe for the threat: \n{self.RecipeRepository[suggestedRecipe]['description']} with parameters: ")
            logging.info(
                f"Impacted host ip: {impacted_host_ip} \nAttacker port: {attacker_port} \nAttacker ip: {attacker_ip}")

    def prepareDataForRemediationOfUnauthorizedAccess(self, alert):

        # self.GlobalScope["AnomalyDetectionSyslog"] = alert.get("AnomalyDetectionSyslog")
        # self.GlobalScope["Threat_Label"] = alert.get("Threat_Label")
        # self.GlobalScope["Classification_Confidence"] = alert("Classification_Confidence")
        # self.GlobalScope["Outlier_Score"] = alert("Outlier_Score")

        self.GlobalScope["UnauthorizedAccessAlert"] = alert

    def cliInput(self):

        while 1:

            prompt = "Insert threat details with this format \n(threat type) (threat name) (impacted host ip) (attacker port) (attacker ip)\n>>> "
            inputData = input(prompt)
            if inputData == "q" or inputData == "Q":
                logging.info("Terminating...")
                sys.exit()
            else:
                inputDataSplit = inputData.split()

            if (inputDataSplit[0] == "malware"):
                logging.info("Remediating malware ...")
                self.prepareDataForRemediationOfMalware(inputDataSplit[0],
                                                        inputDataSplit[1],
                                                        inputDataSplit[2],
                                                        inputDataSplit[3],
                                                        inputDataSplit[4])
            else:
                logging.info("Unsupported threat remediation ...")
                logging.info("Only malware remediation is supported at the moment!")

            self.recipeToRun = self.selectRecipeManually()

            self.remediate()

    def fileInput(self):

        if (len(sys.argv) < 2):
            # In case no input filename is given exit
            # logging.info("No input file given, terminating...")
            # sys.exit()
            fileName = "alert2.json"
        else:
            # In case no input filename is given use by default alert.json
            fileName = sys.argv[1]

        with open(fileName, "r", encoding='utf8') as alertFile:
            alert = json.load(alertFile)
            self.jsonInput(alert)

    def stringInputNetflow(self,threat_report_netflow):
        alerts = json.loads(threat_report_netflow)
        for alert in alerts:
            alert["Threat_Name"] = "malware"
        self.jsonInput(alerts)

    def stringInputSyslog(self,threat_report_syslog):
        alerts = json.loads(threat_report_syslog)
        for alert in alerts:
            alert["Threat_Name"] = "unauthorized_access"
        self.jsonInput(alerts)

    def jsonInput(self, alerts):

        logging.info(alerts)

        self.ServiceGraph.plot()

        for alert in alerts:
            if alert["Threat_Name"] == "unauthorized_access":
                # alert of type unauthorized_access
                self.prepareDataForRemediationOfUnauthorizedAccess(alert)
                bestRecipeName = self.selectBestRecipe(alert["Threat_Name"], alert["Threat_Label"])
                self.recipeToRun = self.RecipeRepository[bestRecipeName]["value"]
                self.setCapabilitiesToSecurityControlMappings(self.RecipeRepository[bestRecipeName]["requiredCapabilities"])
            else:
                # alert of type malware
                self.prepareDataForRemediationOfMalware(alert["Threat_Name"],  # malware
                                                        alert["Threat_Label"],  # command_control / Cridex / Zeus
                                                        alert["Threat_Finding"]["Source_Address"],
                                                        # alert["Threat_Finding"]["Source_Address"],
                                                        alert["Threat_Finding"]["Destination_Port"],
                                                        # alert["Threat_Finding"]["Destination_Port"],  # 22
                                                        alert["Threat_Finding"][
                                                            "Destination_Address"])  # alert["Threat_Finding"]["Destination_Address"]) # 54.154.132.12

                bestRecipeName = self.selectBestRecipe(alert["Threat_Name"], alert["Threat_Label"])
                self.recipeToRun = self.RecipeRepository[bestRecipeName]["value"]
                self.setCapabilitiesToSecurityControlMappings(self.RecipeRepository[bestRecipeName]["requiredCapabilities"])

            self.remediate()

    def remediate(self):

        if self.recipeToRun is None:
            raise Exception("Recipe has not been set")

        # make recipe string readable by the interpreter
        rawSentences = nltk.line_tokenize(self.recipeToRun)
        logging.info("Tokenized per line")
        sentences = []
        for sentence in rawSentences:
            sentences.append(sentence.strip())  # remove trailing and leading extra white spaces
        logging.info("Removed trailing and leading whitespaces")

        # the call to interpret() will run the interpreter with te selected recipe
        logging.info("Launching interpreter ...")
        self.GlobalScope["rowCursor"] = 0
        self.interpet(statements=sentences, lenght=len(sentences), scope=self.GlobalScope)
        # self.getSTIXReport()
        # self.getCACAORemediationPlaybook()

    def selectRecipeManually(self):
        """Manually select which recipe to apply, according to the list shown in the terminal.
        Returns the string of the selected recipe."""

        while (True):
            print(
                "1) Filter payload on impacted node\n"
                "2) Filter ip and port on impacted node\n"
                "3) Monitor traffic on impacted node\n"
                "4) Put impacted nodes into reconfiguration net\n"
                "5) Redirect DNS queries directed to malicious domains\n"
                "6) Add honeypot for each impacted node\n"
                "7) Shutdown impacted nodes\n"
                "8) Isolate impacted nodes\n"
                "Q) Quit"
                ""
            )

            choice = input("Select the recipe to apply: \n>>> ")
            if choice == "q" or choice == "Q":
                print("Terminating...")
                sys.exit()
            elif int(choice) == 1:
                return filter_payload_recipe
                # with open("./interpreterTest2.txt", "r", encoding='utf8') as file:
                #     content = file.read()
            elif int(choice) == 2:
                return filter_ip_port_recipe
            elif int(choice) == 3:
                return monitor_traffic_recipe
            elif int(choice) == 4:
                return put_into_reconfiguration_recipe
            elif int(choice) == 5:
                return redirect_domains_recipe
            elif int(choice) == 6:
                return add_honeypot_recipe
            elif int(choice) == 7:
                return shutdown_recipe
            elif int(choice) == 8:
                return isolate_recipe
            else:
                print("Invalid input")

    def list_paths(self, tokens, scope):
        if len(tokens) < 5:  # for now very basic syntax checking
            raise Exception("Malformed statement: too few arguments")

        source = tokens[2].replace("'", "")
        if source == tokens[2]:
            source = self.getContextVar(source, scope)
        destination = tokens[4].replace("'", "")
        if destination == tokens[4]:
            destination = self.getContextVar(destination, scope)

        # logging post-tokenization
        logging.info(tokens[0] + " " + tokens[1] + " " + f"{source}" + " " + tokens[3] + " " + f"{destination}")

        scope["path_list"] = self.ServiceGraph.list_paths(source, destination)

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

            logging.info(
                tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + f"{nodeType}" + " " + tokens[4] + " " + f"{path}")
            found_node = self.ServiceGraph.find_node_in_path(path, nodeType, capabilities)
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
            logging.info(tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + f"{nodeType}" + " " + tokens[
                4] + " " + f"{node1}" + " " + tokens[6] + " " + f"{node2}")
            new_node = self.ServiceGraph.add_node(node1, node2, nodeType)
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
            logging.info(
                tokens[0] + " " + tokens[1] + " " + f"{node}" + " " + tokens[3] + " " + f"{path}" + " " + tokens[5])
            new_node = self.ServiceGraph.add_firewall(node, path, capabilities)
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
            logging.info(tokens[0] + " " + "rules" + " " + tokens[
                2] + " " + f"{node}")  # logging only "rules" otherwise output gets jammed

            translatedRules = []
            for rule in rules:
                if rule["level"] == 4:
                    translatedRules.append(self.generateRule("level_4_filtering", rule))
                else:
                    translatedRules.append(self.generateRule("level_7_filtering", rule))

            self.ServiceGraph.add_filtering_rules(node, translatedRules)

        except Exception as ex:
            raise ex  # just rethrow it for now

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
            logging.info(tokens[0] + " " + tokens[1] + " " + f"{domain}" + " " + tokens[3] + " " + tokens[
                4] + " " + f"{rule_type}")
            self.ServiceGraph.add_dns_policy(domain, rule_type)
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
            logging.info(tokens[0] + " " + f"{node}")
            self.ServiceGraph.shutdown(node)
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
            logging.info(tokens[0] + " " + f"{node}")
            self.ServiceGraph.isolate(node)
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
            logging.info(tokens[0] + " " + tokens[1] + " " + f"{vulnerability}")
            new_node = self.ServiceGraph.add_honeypot(vulnerability)
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
            logging.info(tokens[0] + " " + tokens[1] + " " + f"{node}" + " " + tokens[3] + " " + f"{path}")
            new_node = self.ServiceGraph.add_network_monitor(node, path)
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
            logging.info(tokens[0] + " " + f"{node}" + " " + tokens[2] + " " + f"{net}")
            self.ServiceGraph.move(node, net)
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

            logging.info(tokens[0] + " " + f"{functionName}")
            function = EnvironmentFunctions.FunctionMappings[functionName]
            if len(tokens)>2:
                function(self.GlobalScope[tokens[2]])
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

    def setContextVar(self, key, scope, newValue):
        # sets the value of the given variable found searching starting from the innermost scope
        if key in scope:
            scope[key] = newValue
            return newValue
        if "outerScope" in scope:
            return self.setContextVar(key, scope["outerScope"], newValue)
        raise Exception(f"Can't find this variable in the program stack: {key}")

    def evaluateRow(self, riga, scope, sentences):
        # this function is called on each row of the "program" and for each one executes
        # the relative construct "if/iterate_on" or calls the given function

        # tokens = nltk.word_tokenize(riga) # this splits also on '
        tokens = riga.split(" ")

        if tokens[0] == "list_paths":
            # sets the variable path_list in the scope. path_list will contain a list of paths
            logging.info("Now calling list_paths function ...")
            self.list_paths(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "find_node":
            # sets found_node to the name of the first node found on the path, if one is not found set to None
            # sets found to true or false
            logging.info("Now calling find_node function ...")
            self.find_node(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_node":
            # adds a node of the specified type between two nodes
            # sets the new_node variable on the scope
            logging.info("Now calling add_node function ...")
            self.add_node(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_firewall":
            # takes a node name and a path as input
            # puts a firewall right behind the node on that path
            # example giving as input node2 and the following path as a list in the same order as displayed:
            # node1 <---> node2 <---> node3 <---> node4
            # node1 <---> node2 <---> firewall <---> node3 <---> node4
            logging.info("Now calling add_firewall function ...")
            self.add_firewall(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_honeypot":
            # adds a new host with the given vulnerability in the honey net
            logging.info("Now calling add_honeypot function ...")
            self.add_honeypot(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_network_monitor":
            # takes a node name and a path as input
            # puts a network monitor node right behind the node on that path
            # example giving as input node2 and the following path as a list in the same order as displayed:
            # node1 <---> node2 <---> node3 <---> node4
            # node1 <---> node2 <---> netowork_monitor <---> node3 <---> node4
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
            # takes a node name as input and shuts it down
            logging.info("Now calling shutdown function ...")
            self.shutdown(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "isolate":
            # takes a node name as input and disconnect all interfaces
            logging.info("Now calling isolate function ...")
            self.isolate(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_filtering_rules":
            # adds the rule to the rule list of the specified firewall node
            # doesn't set anything on the scope
            logging.info("Now calling add_filtering_rules function ...")
            self.add_filtering_rules(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "add_dns_policy":
            # adds the rule to the rule list of the network dns_server node
            # doesn't set anything on the scope
            logging.info("Now calling add_dns_policy function ...")
            self.add_dns_policy(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "execute":
            # executes the function with the name passed as argument
            logging.info("Now calling execute function ...")
            self.execute(tokens, scope)
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "iterate_on":  # "nested iterate" works
            logging.info("Now going into iterate_on construct ...")
            iterateScope = {
                "some_variable_for_iterate_scope": 0,
                "outerScope": scope
            }
            scope["blockStartCursor"] = self.getContextVar("rowCursor", scope) + 1
            nameOfListToIterateOn = tokens[1]
            for item in self.getContextVar(nameOfListToIterateOn, scope):
                iterateScope["iteration_element"] = item
                iterateScope["rowCursor"] = scope["blockStartCursor"]
                self.interpet(statements=sentences, lenght=len(sentences), scope=iterateScope)
                scope["rowCursor"] = iterateScope["rowCursor"]
            return 0
        elif tokens[0] == "if":  # "nested if else" not tested but should work
            logging.info("Now going into if/else construct ...")
            ifScope = {
                "some_variable_for_if_scope": 0,
                "outerScope": scope,
                "rowCursor": self.getContextVar("rowCursor", scope)
            }
            # compute "if" condition, considering potential "not" keyword
            condition = (not self.getContextVar(tokens[2], scope)) if tokens[1] == "not" else self.getContextVar(
                tokens[1], scope)

            if (condition):
                # condition true -> take if branch
                # execute normally with interpret. when encountering else or endif will return here and set outer rowCursor to after the endif
                ifScope["rowCursor"] = self.getContextVar("rowCursor", scope) + 1
                self.interpet(statements=sentences, lenght=len(sentences), scope=ifScope)
                for index, item in enumerate(sentences[ifScope["rowCursor"] - 1:], start=ifScope["rowCursor"] - 1):
                    if item == "endif":
                        scope["rowCursor"] = index + 1
                        break
                return 0
            else:
                # condition false -> take else branch
                # jump to after else (set rowcursor) or endif and continue normally with interpret, then when ecnountering endif will return here and set outer rowCursor to after the endif
                for index, item in enumerate(sentences[ifScope["rowCursor"]:], start=ifScope["rowCursor"]):
                    if item == "else":
                        ifScope["rowCursor"] = index + 1
                        self.interpet(statements=sentences, lenght=len(sentences), scope=ifScope)
                        for index2, item2 in enumerate(sentences[ifScope["rowCursor"]:], start=ifScope["rowCursor"]):
                            if item2 == "endif":
                                scope["rowCursor"] = index2 + 1
                                return 0
                    if item == "endif":
                        scope["rowCursor"] = index + 1
                        return 0
        elif tokens[0] == "enditeration":  # end of iteration loop -> return to calling intrpreter
            logging.info("Exiting iteration construct")
            scope["rowCursor"] += 1
            return 1
        elif tokens[0] == "endif":  #  end of if block -> return to calling interpreter
            logging.info("Exiting if/else construct")
            scope["rowCursor"] += 1
            return 1
        elif tokens[0] == "else":  #  end of if branch -> return to calling interpreter
            logging.info("Now exiting if/else construct")
            scope["rowCursor"] += 1
            return 1
        elif tokens[0] == "testIf":  # just print testIf
            logging.info("testIf executed")
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "testElse":  # just print testElse
            logging.info("testElse executed")
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "invertCondizioneTest":
            if self.getContextVar("condizioneTest", scope):
                self.setContextVar("condizioneTest", scope, False)
            else:
                self.setContextVar("condizioneTest", scope, True)
            logging.info("invertCondizioneTest executed")
            logging.info(scope["iteration_element"])
            scope["rowCursor"] += 1
            return 0
        elif tokens[0] == "actionThatDoesNothing":
            logging.info("actionThatDoesNothing executed")
            logging.info(scope["iteration_element"])
            scope["rowCursor"] += 1
            return 0
        else:
            logging.info(f"Unrecognized statement: {tokens[0]}")
            raise Exception(f"Unrecognized statement: {tokens[0]}")

    def interpet(self, statements, lenght, scope):
        # This is the interpreter, that loops on the program rows and calls the evaluateRow for evaluating them
        # It can be recursevely called from language constructs, for example an iteration statement calls it on
        # each loop, and once the iteration block is completely executed control is returned to the outer
        # interpreter (see break call inside the {if result == 1} ).
        # interpret() is called recursively when encountering a block construct ie (while, if).

        # Shows starting state of the landscape
        self.ServiceGraph.plot()

        logging.info("Starting interpreter parsing ...")
        while (self.getContextVar("rowCursor", scope) < lenght):
            result = self.evaluateRow(statements[self.getContextVar("rowCursor", scope)], scope, statements)
            if result == 1:  # for ending iteration and if blocks
                break

def main():

    ####################### CLI input examples ########################
    # malware command_control 10.1.0.10 22 12.12.12.12                #
    # malware Cridex 10.1.0.10 22 12.12.12.12                         #
    # malware Zeus 10.1.0.10 22 12.12.12.12                           #
    # malware Neptune 10.1.0.10 22 12.12.12.12                        #
    ###################################################################

    with open("SecurityControlRepository.json", "r", encoding='utf8') as SecurityControlRepositoryFile:
        securityControlRepository = json.load(SecurityControlRepositoryFile)["SecurityControls"]
    with open("ThreatRepository.json", "r", encoding='utf8') as ThreatRepositoryFile:
        threatRepository = json.load(ThreatRepositoryFile)["Threats"]

    remediator = Remediator(SecurityControlRepository=securityControlRepository,
                            ThreatRepository=threatRepository)

    #remediator.fileInput()
    #remediator.cliInput()
    remediator.stringInputNetflow("[{ \"Threat_Finding\": { \"Time_Start\": \"2021-06-03 01:32:07\", \"Time_End\": \"2021-06-03 03:41:22\", \"Time_Duration\": 7755.566, \"Source_Address\": \"10.1.0.10\", \"Destination_Address\": \"1.2.3.4\", \"Source_Port\": 4897, \"Destination_Port\": 443, \"Protocol\": \"TCP\", \"Flag\": \"...A.R..\",  \"Soure_tos\": 0, \"Input_packets\": 6, \"Input_bytes\": 276}, \"Threat_Label\": \"Cridex\", \"Classification_Confidence\": 0.92, \"Outlier_Score\": -0.5}]")

if __name__ == "__main__":

    main()

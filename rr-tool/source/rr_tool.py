import copy
import json
import os
import sys
from typing import Dict

from helpers import igraph_helper
from input_analyzer import input_analyzer
from recipe_interpreter import recipe_interpreter
from recipe_filter import recipe_filter
import service_graph
import settings
from helpers.rr_tool_helper import load_json_folder_as_dict
from settings import TOOL_DIR
from helpers.logging_helper import get_logger

logger = get_logger('rr-tool')


class RRTool:

    def __init__(self,
                 security_control_repository: Dict = None,
                 threat_repository: Dict = None,
                 recipe_repository: Dict = None,
                 recipe_to_run: str = None,
                 global_scope: Dict = None,
                 env: Dict = None) -> None:
        if env is not None:
            logger.info("Reading custom environment variables")
            for key in env.keys():
                settings.key = env[key]

        logger.info("Initializing security controls repository")
        if security_control_repository is None:
            self.security_control_repository = load_json_folder_as_dict(TOOL_DIR, "kb/security_controls")
            # check if a translator is available for each security control in repository
            translators_folder = TOOL_DIR.joinpath("source/security_controls")
            if settings.ENABLE_ONLY_SECURITY_CAPABILITIES_WITH_TRANSLATOR == "1":
                for security_control_name, security_control in self.security_control_repository.items():
                    security_control['has_translator'] = 'False'
                    for file_name in translators_folder.glob('*'):
                        if file_name.stem == security_control_name:
                            security_control['has_translator'] = 'True'
                            break
        else:
            self.security_control_repository = copy.deepcopy(security_control_repository)
        logger.debug("Security control repository loaded: " +
                     str(self.security_control_repository))

        self.capability_to_security_control_mappings = {}
        # TODO infer from security_control_repository
        # logger.info("Initializing capability-security_controls mapping")
        # self.capability_to_security_control_mappings = {
        #     "level_4_filtering": "iptables",
        #     "level_7_filtering": "generic_level_7_filter",
        #     "level_4_monitor": "generic_network_traffic_monitor"
        # }
        # logger.debug("Capability-security_controls mapping loaded: " +
        #              str(self.capability_to_security_control_mappings))

        if settings.IGRAPH_PICTURES_OUTPUT_FOLDER != "":
            logger.info("Clearing graph folder")
            igraph_helper.clear_graph_folder()

        logger.info("Initializing threat repository")
        if threat_repository is None:
            self.threat_repository = load_json_folder_as_dict(TOOL_DIR, "kb/threats")
        else:
            self.threat_repository = threat_repository
        logger.debug("Threat repository loaded: " + str(self.threat_repository))

        logger.info("Initializing recipe repository")
        if recipe_repository is None:
            self.recipe_repository = load_json_folder_as_dict(TOOL_DIR, "kb/recipes", ".rec")
        else:
            self.recipe_repository = recipe_repository

        logger.debug("Recipe repository loaded: " + str(self.recipe_repository))

        self.recipeToRun = recipe_to_run

        logger.info("Initializing service graph")
        self.service_graph_instance = service_graph.ServiceGraph()

        logger.info("Initializing Recipe Filter")
        self.recipe_filter_instance = recipe_filter.RecipeFilter(self.threat_repository,
                                                                 self.security_control_repository,
                                                                 self.recipe_repository)

        logger.info("Initializing global scope")
        if global_scope is None:
            self.global_scope = {}

    def setCapabilitiesToSecurityControlMappings(self, required_capabilities: list):
        """Sets the CapabilityToSecurityControlMappings dictionary according to the capabilities needed for
        the execution of the selected recipe. Each capability is mapped to the respective security control
        that will be used to enforce that capability.
        Returns nothing"""

        for el in required_capabilities:
            for key, value in self.security_control_repository.items():
                if el in value["capabilities"]:
                    self.capability_to_security_control_mappings[el] = key
                    break

    def cliInput(self):

        while 1:

            prompt = "Insert threat details with this format \n(threat type) (threat name) (impacted host ip) " \
                     "(attacker port) (attacker ip)\n>>> "
            inputData = input(prompt)
            if inputData == "q" or inputData == "Q":
                logger.info("Terminating...")
                sys.exit()
            else:
                inputDataSplit = inputData.split()

            if inputDataSplit[0] == "malware":
                logger.info("Remediating malware ...")
                input_analyzer.prepareDataForRemediationOfMalware(
                    global_scope=self.global_scope,
                    service_graph_instance=self.service_graph_instance,
                    threat_repository=self.threat_repository,
                    threat_category=inputDataSplit[0],
                    threat_label=inputDataSplit[1],
                    impacted_host_ip=inputDataSplit[2],
                    attacker_port=inputDataSplit[3],
                    attacker_ip=inputDataSplit[4],
                    impacted_host_port="",
                    protocol="")
            else:
                logger.info("Unsupported threat remediation ...")
                logger.info("Only malware remediation is supported at the moment!")

            self.recipeToRun = self.selectRecipeManually()

            recipe_interpreter. \
                RecipeInterpreter(self.service_graph_instance,
                                  self.global_scope,
                                  self.capability_to_security_control_mappings).remediate(self.recipeToRun)

    def folderInput(self, folder_name, alert_type):
        only_files = [f for f in os.listdir(folder_name) if os.path.isfile(os.path.join(folder_name, f))]
        for f in only_files:
            logger.info("Reading alert file " + folder_name + os.sep + f)
            self.fileInput(folder_name + os.sep + f, alert_type)

    def fileInput(self, file_name, alert_type):

        with open(file_name, "r", encoding='utf8') as alertFile:
            alert = json.load(alertFile)
            if alert_type == "netflow":
                self.jsonInput(alert)
            elif alert_type == "syslog":
                alert["Threat_Category"] = "unauthorized_access"
                self.jsonInput(alert)
            else:
                logger.error("Unknown alert type: " + alert_type)

    def stringInputNetflow(self, threat_report_netflow):
        logger.info("Threat report netflow: " + threat_report_netflow)
        alert = json.loads(threat_report_netflow)
        logger.info("Serialized netflow threat report: " + str(alert))
        self.jsonInput(alert)

    def stringInputSyslog(self, threat_report_syslog):
        logger.info("Threat report syslog: " + threat_report_syslog)
        alert = json.loads(threat_report_syslog)
        logger.info("Serialized syslog threat report: " + str(alert))
        alert["Threat_Category"] = "unauthorized_access"
        self.jsonInput(alert)

    def performProactiveRemediation(self, proactive_alert):

        instance_identifier = settings.RR_INSTANCE_ID
        if proactive_alert["rr_tool_instance_id"] == instance_identifier:
            # The instance received a message produced by itself. Just ignore it
            print("Ignoring proactive alert sent by me")
            return

        logger.info(proactive_alert)

        self.service_graph_instance.plot()

        try:
            proactive_alert["threat_category"] = str(proactive_alert["threat_category"]).casefold()
        except KeyError:
            logger.error("Malformed alert received (threat category missing), skipping...")
            return

        bestRecipeName = self.recipe_filter_instance.selectBestRecipe(proactive_alert["threat_category"],
                                                            proactive_alert["threat_label"],
                                                            proactive=True,
                                                            availableArtifacts=proactive_alert["recipe_data"])

        logger.info(f"Selected recipe for proactive remediation: ( \
                    {self.recipe_repository[bestRecipeName]['description']})")

        try:
            input_analyzer.\
                prepareDataForBotnetProactiveRemediation(global_scope=self.global_scope,
                                                threat_repository=self.threat_repository,
                                                threat_category=proactive_alert["threat_category"],
                                                threat_label=proactive_alert["threat_label"],
                                                artifacts=proactive_alert["recipe_data"])
        except KeyError:
            logger.error("Malformed alert received, skipping...")
            return

        self.setCapabilitiesToSecurityControlMappings(
                                        self.recipe_repository[bestRecipeName]["requiredCapabilities"])

        recipe_interpreter_instance = recipe_interpreter.RecipeInterpreter(self.service_graph_instance,
                                                                self.global_scope,
                                                                self.capability_to_security_control_mappings)

        recipe_interpreter_instance.remediate_new(bestRecipeName)

    def addNewAttackRemediation(self, msg):
        logger.info("New attack remediation: " + msg)
        new_attack_remediation = json.loads(msg)
        logger.info("Serialized new attack remediation: " + str(msg))

        threat_description = {}
        threat_description["rules"] = new_attack_remediation["threat_description"]["rules"]
        threat_description["recipes"] = new_attack_remediation["threat_description"]["recipes"]

        folder_name = new_attack_remediation["threat_description"]["threat_category"]
        file_name = new_attack_remediation["threat_description"]["threat_label"]

        #### Threats folder changes ####

        # print("CWD: " + os.getcwd()) # for path issues troubleshooting

        # Construct the relative path to the destination folder
        dst_folder = f"./kb/threats/{folder_name}"

        # Create the full path to the outfile
        outfile_path = os.path.join(dst_folder, f"{file_name}.json")

        # Create the destination folder if it does not exist
        if not os.path.exists(dst_folder):
            os.makedirs(dst_folder)

        # Open the outfile and write the recipe_text to it
        with open(outfile_path, 'w', encoding='utf8') as outfile:
            json.dump(threat_description, outfile, indent=4)

        #### Recipes folder changes ####

        # Construct the relative path to the destination folder
        dst_folder = './kb/recipes'

        for recipe in new_attack_remediation["recipes"]:
            recipe_name = recipe["recipe_name"]
            recipe_text = recipe["recipe_text"]
            recipe_description = {"description": recipe["description"],
                                "requiredCapabilities": recipe["requiredCapabilities"],
                                "requiredArtifacts": recipe["requiredArtifacts"]}

            # Create the full path to the outfile
            outfile_path = os.path.join(dst_folder, f"{recipe_name}.rec")
            with open(outfile_path, 'w', encoding='utf8') as outfile:
                outfile.write(recipe_text)

            # Create the full path to the outfile
            outfile_path = os.path.join(dst_folder, f"{recipe_name}.json")
            with open(outfile_path, 'w', encoding='utf8') as outfile:
                json.dump(recipe_description, outfile, indent=4)


    def jsonInput(self, alert):

        logger.info(alert)

        self.service_graph_instance.plot()

        # TODO evaluate if multiple alerts in the same json should be supported
        # for alert in alerts:
        try:
            alert["Threat_Category"] = str(alert["Threat_Category"]).casefold()
        except KeyError:
            logger.error("Malformed alert received (threat category missing), skipping...")
            return

        # TODO here we should give present the user with the best recipe and
        #  if automatic remediation mode is disabled allow him to accept the hint or select another recipe
        bestRecipeName = self.recipe_filter_instance.selectBestRecipe(alert["Threat_Category"],
                                                                        alert["Threat_Label"],
                                                                        proactive=False,
                                                                        availableArtifacts=[])
        logger.info(f"Recommended recipe for the threat: ( {self.recipe_repository[bestRecipeName]['description']})")

        # TODO create a generic prepareData function in input analyzer
        recipeToRun = self.recipe_repository[bestRecipeName]["value"]
        if alert["Threat_Category"] == "unauthorized_access":
            # alert of type unauthorized_access
            try:
                input_analyzer. \
                    prepareDataForRemediationOfUnauthorizedAccess(global_scope=self.global_scope,
                                                                  service_graph_instance=self.service_graph_instance,
                                                                  alert=alert)

                self.setCapabilitiesToSecurityControlMappings(
                    self.recipe_repository[bestRecipeName]["requiredCapabilities"])
            except KeyError:
                logger.error("Malformed alert received, skipping...")
                return
        elif alert["Threat_Category"] == "botnet":
            # alert of type malware
            try:
                input_analyzer. \
                    prepareDataForRemediationOfMalware(global_scope=self.global_scope,
                                                       service_graph_instance=self.service_graph_instance,
                                                       threat_repository=self.threat_repository,
                                                       threat_category=alert["Threat_Category"],
                                                       threat_label=alert["Threat_Label"],
                                                       protocol=alert["Threat_Finding"]["Protocol"],
                                                       impacted_host_port=alert["Threat_Finding"]["Source_Port"],
                                                       impacted_host_ip=alert["Threat_Finding"]["Source_Address"],
                                                       attacker_port=alert["Threat_Finding"]["Destination_Port"],
                                                       attacker_ip=alert["Threat_Finding"]["Destination_Address"])
            except KeyError:
                logger.error("Malformed alert received, skipping...")
                return
            self.setCapabilitiesToSecurityControlMappings(
                self.recipe_repository[bestRecipeName]["requiredCapabilities"])

        recipe_interpreter_instance = recipe_interpreter.RecipeInterpreter(self.service_graph_instance,
                                                                self.global_scope,
                                                                self.capability_to_security_control_mappings)
        #recipe_interpreter_instance.remediate(recipeToRun)

        recipe_interpreter_instance.remediate_new(bestRecipeName)

        #todo send proactive after having filtered private data

    def selectRecipeManually(self):
        """Manually select which recipe to apply, according to the list shown in the terminal.
        Returns the string of the selected recipe."""

        while True:

            index = 1
            recipe_list = []
            for recipe in self.recipe_repository:
                print(str(index) + ") " + recipe['description'])
                recipe_list.append(recipe)
                index += 1
            print("Q) Quit")

            choice = input("Select the recipe to apply: \n>>> ")

            if choice == "q" or choice == "Q":
                print("Terminating...")
                sys.exit()
            elif int(choice) == 1:
                return recipe_list[int(choice)]
            else:
                print("Invalid input")

def main():

    match settings.RR_TOOL_MODE:
        case "standalone":
            os.chdir("./rr-tool")
            rr_tool_instance = RRTool()
            rr_tool_instance.folderInput(sys.argv[1], sys.argv[2])
            rr_tool_instance.service_graph_instance.plot()

        case "kafka":
            from connectors import kafka_consumer
            kafka_consumer.consume_topics(RRTool())
        case _:
            logger.error("Unknown RR_TOOL_MODE: "+settings.RR_TOOL_MODE)


if __name__ == "__main__":
    main()

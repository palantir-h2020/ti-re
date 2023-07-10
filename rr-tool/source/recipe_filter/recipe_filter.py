from typing import Dict

import settings

from helpers.logging_helper import get_logger

logger = get_logger('recipe-filter')


def output_applicability_report(applicable_recipes, not_applicable_recipes):
    logger.debug("Applicable recipes for threat: " + str(applicable_recipes))
    logger.debug("Not applicable recipes for threat: " + str(not_applicable_recipes))
    # TODO add unsatisfied capabilities to not applicable recipes report
    pass


class RecipeFilter:

    def __init__(self,
                 threat_repository: Dict,
                 security_control_repository: Dict,
                 recipe_repository: Dict) -> None:
        self.threat_repository = threat_repository
        self.recipe_repository = recipe_repository
        self.security_control_repository = security_control_repository

    def selectBestRecipe(self, threat_category, threat_label, proactive=False, availableArtifacts=[]):
        """Selects the best recipe enforceable for the given threat taking into account the priority of recipes. If
        a given recipe requires a capability not enforceable with any security control available in the
        SecurityControlsRepository it will return the next one in line that can be enforced.
        Returns the name of the selected recipe."""

        logger.info("Finding best recipe to remediate threat " + threat_category + "/" + threat_label)

        applicable_recipes = {}
        not_applicable_recipes = {}

        maxPriority = 0
        bestRecipeName = None
        try:
            recipesForThreat = self.threat_repository[threat_category][threat_label]["recipes"]
        except KeyError:
            recipesForThreat = self.threat_repository[threat_category]["unknown"]["recipes"]
        for el in recipesForThreat:
            isEnforceable = self.checkEnforceability(el["recipeName"])
            # for now availability requirements are only checked for proactive remediation
            if proactive:
                # the following line is used to check if the recipe is compatible with proactive remediation
                isProactiveCompatible = self.checkProactiveCompatibility(el["recipeName"], proactive)
                areRequiredArtifactsAvailable = self.checkArtifactsAvailability(el["recipeName"], availableArtifacts)
            else:
                areRequiredArtifactsAvailable = True
                isProactiveCompatible = True
            if el["priority"] > maxPriority and isEnforceable and isProactiveCompatible and areRequiredArtifactsAvailable:
                maxPriority = el["priority"]
                bestRecipeName = el["recipeName"]
            if isEnforceable and isProactiveCompatible and areRequiredArtifactsAvailable:
                applicable_recipes[el["recipeName"]] = el
            else:
                not_applicable_recipes[el["recipeName"]] = el

        output_applicability_report(applicable_recipes, not_applicable_recipes)

        logger.debug("Best recipe to remediate threat " + threat_category + "/" + threat_label + ": " + bestRecipeName)

        return bestRecipeName

    def checkProactiveCompatibility(self, recipe_name, proactive):
        """Checks whether the recipe's remediation can be performed when a proactive attack alert is received
        from other RR-tool instances. If the attack alert is not a proctive one, no check is needed"""

        logger.info("Checking proactive remediation compatibility for recipe " + recipe_name)

        if proactive is False:
            return True

        if proactive is True and self.recipe_repository[recipe_name]["proactive"] is True:
            return True
        else:
            return False


    def checkEnforceability(self, recipe_name):
        """Checks the enforceability of a given recipe, that is, for every required capability a SecurityControl
        capable of enforcing it is available in the SecurityControlRepository"""

        logger.info("Checking enforceability for recipe " + recipe_name)

        # Get the set of required capabilities from the RecipeRepository
        requiredCapabilities = set(self.recipe_repository[recipe_name]["requiredCapabilities"])

        # Get the set of enforceable capabilities from the SecurityControlRepository
        enforceableCapabilities = set()
        for el in self.security_control_repository.values():
            if settings.ENABLE_ONLY_SECURITY_CAPABILITIES_WITH_TRANSLATOR == "1":
                if el["has_translator"] == 'False':
                    continue
            enforceableCapabilities.update(el["capabilities"])

        if requiredCapabilities.issubset(enforceableCapabilities):
            return True
        else:
            return False

    def checkArtifactsAvailability(self, recipe_name, availableArtifacts):
        """Checks whether the artifacts required for a recipe remediation are available"""

        logger.info("Checking artifacts availability for recipe " + recipe_name)

        # Get the set of required artifacts from the RecipeRepository
        requiredArtifacts = set(self.recipe_repository[recipe_name]["requiredArtifacts"])

        if requiredArtifacts.issubset(set(availableArtifacts)):
            logger.info("OK, required artifacts available")
            return True
        else:
            logger.error("Required artifacts missing")
            logger.info("Available: " + str(set(availableArtifacts)))
            logger.info("Required: " + str(set(requiredArtifacts)))
            return False
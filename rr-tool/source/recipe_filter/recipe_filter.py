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

    def selectBestRecipe(self, threat_name, threat_label):
        """Selects the best recipe enforceable for the given threat taking into account the priority of recipes. If
        a given recipe requires a capability not enforceable with any security control available in the
        SecurityControlsRepository it will return the next one in line that can be enforced.
        Returns the name of the selected recipe."""

        logger.debug("Finding best recipe to remediate threat " + threat_name + "/" + threat_label)

        applicable_recipes = {}
        not_applicable_recipes = {}

        maxPriority = 0
        bestRecipeName = None
        try:
            recipesForThreat = self.threat_repository[threat_name][threat_label]["recipes"]
        except KeyError:
            recipesForThreat = self.threat_repository[threat_name]["unknown"]["recipes"]
        for el in recipesForThreat:
            isEnforceable = self.checkEnforceability(el["recipeName"])
            if el["priority"] > maxPriority and isEnforceable:
                maxPriority = el["priority"]
                bestRecipeName = el["recipeName"]
            if isEnforceable:
                applicable_recipes[el["recipeName"]] = el
            else:
                not_applicable_recipes[el["recipeName"]] = el

        output_applicability_report(applicable_recipes, not_applicable_recipes)

        logger.debug("Best recipe to remediate threat " + threat_name + "/" + threat_label + ": " + bestRecipeName)

        return bestRecipeName

    def checkEnforceability(self, recipe_name):
        """Checks the enforceability of a given recipe, that is, for every required capability a SecurityControl
        capable of enforcing it is available in the SecurityControlRepository"""

        logger.debug("Checking enforceability for recipe " + recipe_name)
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

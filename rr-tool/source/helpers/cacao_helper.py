import json
import base64
import helpers.cacao_generator as cacao

from helpers.logging_helper import get_logger

logger = get_logger('cacao_helper')

def getCACAOPlaybook(global_scope, recipe_text, threat_type):

    recipe_abstraction = cacao.Recipe(recipe_text, global_scope)

    # with open('cacaoPlaybook.json', 'w', encoding='utf8') as outfile:
    #     json.dump(ricetta.toCACAOPlaybook().toDict(), outfile, indent=4)

    playbook_json = json.dumps(recipe_abstraction.toCACAOPlaybook().toDict(), indent=4)

    # Encode the string as base64
    playbook_base64_bytes = base64.b64encode(playbook_json.encode('utf-8'))

    # Decode the base64 bytes to a string
    playbook_base64_string = playbook_base64_bytes.decode('utf-8')

    logger.info(f"Produced CACAO Security Playbook Report")

    return playbook_json, playbook_base64_string
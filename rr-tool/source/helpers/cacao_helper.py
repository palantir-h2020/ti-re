import json
import base64



def getCACAOPlaybook(global_scope, threat_type):

    playbook = {"test_playbook": "test"}
    playbook_json = json.dumps(playbook)

    # Encode the string as base64
    playbook_base64_bytes = base64.b64encode(playbook_json.encode('utf-8'))

    # Decode the base64 bytes to a string
    playbook_base64_string = playbook_base64_bytes.decode('utf-8')

    return playbook_json, playbook_base64_string
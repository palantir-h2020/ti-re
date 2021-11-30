import logging
import nltk
import serviceGraph

logging.basicConfig(level=logging.DEBUG)

filter_payload_recipe_old = "list_paths from 'host1' to 'attacker'\n                        \
    iterate_on path_list\n                                                              \
        find_node of type 'filtering_node'\n                                            \
        if not found:\n                                                                 \
            add_node of type 'filtering_node' between impacted_node and threat_source\n   \
            add_rule attack_payload to new_node payload filtering list\n                \
        else\n                                                                          \
            add_rule attack_payload to filtering_node payload filtering list\n          \
        endif\n                                                                         \
    enditeration"

# Sample program for nested "iterate" constructs and "if" construct testing.
interpreterTest1 = "iterate_on listTest1\n                                       \
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

interpreterTest2 ="list_paths from 'host1' to 'attacker'                                                         \n\
                    iterate_on path_list                                                                     \n\
                        find_node of type 'firewalll' in iteration_element                                   \n\
                        if not found                                                                         \n\
                            add_firewall behind 'host1' in iteration_element                                 \n\
                            add_filtering_rule 'filter_payload_X' to new_node                                \n\
                            add_honeypot with 'nginx_vulnerability'                                          \n\
                        else                                                                                 \n\
                            add_filtering_rule 'filter_payload_X' to found_node                              \n\
                        endif                                                                                \n\
                        if found                                                                             \n\
                            add_firewall behind 'host1' in iteration_element                                 \n\
                        else                                                                                 \n\
                            add_firewall behind 'gateway' in iteration_element                               \n\
                        endif                                                                                \n\
                    enditeration                                                                             \n\
                    iterate_on path_list                                                                     \n\
                        testIf                                                                                \n\
                    enditeration"
filter_payload_recipe ="list_paths from impacted_host_ip to 'attacker'                                           \n\
                        iterate_on path_list                                                                     \n\
                            find_node of type 'firewall' in iteration_element with 'level_7_filtering'                                \n\
                            if not found                                                                         \n\
                                add_firewall behind impacted_host_ip in iteration_element with 'level_7_filtering'                    \n\
                                add_filtering_rules rules_level_7 to new_node                                              \n\
                            else                                                                                 \n\
                                add_filtering_rules rules_level_7 to found_node                              \n\
                            endif                                                                                \n\
                        enditeration"

filter_ip_port_recipe ="list_paths from impacted_host_ip to 'attacker'                                           \n\
                        iterate_on path_list                                                                     \n\
                            find_node of type 'firewall' in iteration_element with 'level_4_filtering'                                \n\
                            if not found                                                                         \n\
                                add_firewall behind impacted_host_ip in iteration_element with 'level_4_filtering'                      \n\
                                add_filtering_rules rules_level_4 to new_node                                              \n\
                            else                                                                                 \n\
                                add_filtering_rules rules_level_4 to found_node                              \n\
                            endif                                                                                \n\
                        enditeration"

monitor_traffic_recipe ="list_paths from impacted_host_ip to 'attacker'                                          \n\
                        iterate_on path_list                                                                     \n\
                            find_node of type 'network_monitor' in iteration_element                             \n\
                            if not found                                                                         \n\
                                add_network_monitor behind impacted_host_ip in iteration_element                 \n\
                            endif                                                                                \n\
                        enditeration"

put_into_reconfiguration_recipe = "iterate_on impacted_nodes                                                     \n\
                                        move iteration_element to 'reconfiguration_net'                          \n\
                                    enditeration"

add_honeypot_recipe = "iterate_on impacted_nodes                                                                 \n\
                            add_honeypot with 'apache_vulnerability'                                             \n\
                        enditeration"

shutdown_recipe = "iterate_on impacted_nodes                                                                     \n\
                        shutdown iteration_element                                                               \n\
                    enditeration"

isolate_recipe = "iterate_on impacted_nodes                                                                      \n\
                    isolate iteration_element                                                                    \n\
                enditeration"

recipeRepository = {
    "filter_payload_recipe": {
        "description": "Filter payload on impacted node",
        "value": filter_payload_recipe
    },
    "filter_ip_port_recipe": {
        "description": "Filter ip and port on impacted node",
        "value": filter_ip_port_recipe
    },
    "monitor_traffic_recipe": {
        "description": "Monitor traffic on impacted node",
        "value": monitor_traffic_recipe
    },
    "put_into_reconfiguration_recipe": {
        "description": "Put impacted nodes into reconfiguration net",
        "value": put_into_reconfiguration_recipe
    },
    "add_honeypot_recipe": {
        "description": "Add honeypot for each impacted node",
        "value": add_honeypot_recipe
    },
    "shutdown_recipe": {
        "description": "Shutdown impacted nodes",
        "value": shutdown_recipe
    },
    "isolate_recipe": {
        "description": "Isolate impacted nodes",
        "value": isolate_recipe
    },
}


#           add_node of type 'firewall' between iteration_element:0 and iteration_element:1 \n\

def list_paths(tokens, scope):
    if len(tokens) < 5: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")

    source = tokens[2].replace("'", "")
    if source == tokens[2]:
        source = getContextVar(source, scope)
    destination = tokens[4].replace("'", "")
    if destination == tokens[4]:
        destination = getContextVar(destination, scope)

    #logging post-tokenization
    logging.info(tokens[0] + " " + tokens[1] + " "+ str(source) + " "+ tokens[3] + " "+ str(destination))

    scope["path_list"] = serviceGraph.list_paths(source, destination)

def find_node(tokens, scope):
    if len(tokens) < 6: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    nodeType = tokens[3].replace("'", "") # node type to search for
    if nodeType == tokens[3]:
        nodeType = getContextVar(nodeType, scope)
    path = tokens[5].replace("'", "") # where to search in for the node
    if path == tokens[5]:
        path = getContextVar(path, scope)

    # Support for additional "capability" argument
    if len(tokens) == 8:
        capability = tokens[7].replace("'", "")
        if capability == tokens[7]:
            capability = getContextVar(capability, scope)
        capabilities = [capability] # for now supports only one capability as input
    else:
        capabilities = []

    try:

        logging.info(tokens[0] + " "+ tokens[1] + " "+ tokens[2] + " "+ str(nodeType) + " "+ tokens[4] + " "+ str(path)) #todo add "with" log
        found_node = serviceGraph.find_node_in_path(path, nodeType, capabilities)
        if found_node != "Not found":
            scope["found_node"] = found_node
            scope["found"] = True
        else:
            scope["found_node"] = None
            scope["found"] = False
    except Exception as ex:
        raise ex

def add_node(tokens, scope):
    if len(tokens) < 8: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    nodeType = tokens[3].replace("'", "")
    if nodeType == tokens[3]:
        nodeType = getContextVar(nodeType, scope)
    node1 = tokens[5].replace("'", "")
    if node1 == tokens[3]:
        node1 = getContextVar(node1, scope)
    node2 = tokens[7].replace("'", "")
    if node2 == tokens[3]:
        node2 = getContextVar(node2, scope)

    try:
        logging.info(tokens[0] + " "+ tokens[1] + " "+ tokens[2] + " "+ str(nodeType)+ " " + tokens[4]+ " " + str(node1) + " "+ tokens[6] + " "+ str(node2))
        new_node = serviceGraph.add_node(node1, node2, nodeType)
        scope["new_node"] = new_node
    except Exception as ex:
        raise ex # just rethrow it for now

def add_firewall(tokens, scope):
    if len(tokens) < 5: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    node = tokens[2].replace("'", "")
    if node == tokens[2]:
        node = getContextVar(node, scope)
    path = tokens[4].replace("'", "")
    if path == tokens[4]:
        path = getContextVar(path, scope)

    # Support for additional "capability" argument
    if len(tokens) == 7:
        capability = tokens[6].replace("'", "")
        if capability == tokens[6]:
            capability = getContextVar(capability, scope)
        capabilities = [capability] # for now supports only one capability as input
    else:
        capabilities = ["level_4_filtering", "level_7_filtering"]

    try:
        logging.info(tokens[0] + " "+ tokens[1] + " "+ str(node) + " "+ tokens[3]+ " " + str(path) + " "+ tokens[5])
        new_node = serviceGraph.add_firewall(node, path, capabilities)
        scope["new_node"] = new_node
    except Exception as ex:
        raise ex # just rethrow it for now

def add_filtering_rules(tokens, scope):
    if len(tokens) < 4: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    node = tokens[3].replace("'", "")
    if node == tokens[3]:
        node = getContextVar(node, scope)
    rules = tokens[1].replace("'", "")
    if rules == tokens[1]:
        rules = getContextVar(rules, scope)

    try:
        logging.info(tokens[0]+ " " + "rules"+ " "+ tokens[2] + " "+ str(node)) # logging only "rules" otherwise output gets jammed
        serviceGraph.add_filtering_rules(node, rules)
    except Exception as ex:
        raise ex # just rethrow it for now

def shutdown(tokens, scope):
    # shutdown 'host1' # can be also a list of nodes
    if len(tokens) < 2: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    node = tokens[1].replace("'", "")
    if node == tokens[1]:
        node = getContextVar(node, scope)

    try:
        logging.info(tokens[0] + " "+ str(node))
        serviceGraph.shutdown(node)
    except Exception as ex:
        raise ex # just rethrow it for now

def isolate(tokens, scope):
    # isolate 'host1' # can be also a list of nodes
    if len(tokens) < 2: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    node = tokens[1].replace("'", "")
    if node == tokens[1]:
        node = getContextVar(node, scope)

    try:
        logging.info(tokens[0] + " "+ str(node))
        serviceGraph.isolate(node)
    except Exception as ex:
        raise ex # just rethrow it for now

def add_honeypot(tokens, scope):
    # add_honeypot with 'apache_vulnerability' # can be also a list of vulnerabilities
    if len(tokens) < 3: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    vulnerability = tokens[2].replace("'", "")
    if vulnerability == tokens[2]:
        vulnerability = getContextVar(vulnerability, scope)

    try:
        logging.info(tokens[0] + " "+ tokens[1] + " "+ str(vulnerability))
        new_node = serviceGraph.add_honeypot(vulnerability)
        scope["new_node"] = new_node
    except Exception as ex:
        raise ex # just rethrow it for now

def add_network_monitor(tokens, scope):
    # add_network_monitor behind 'host1' in path # path is a list of nodes, and in it 'host1' must be present
    if len(tokens) < 5: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    node = tokens[2].replace("'", "")
    if node == tokens[2]:
        node = getContextVar(node, scope)
    path = tokens[4].replace("'", "")
    if path == tokens[4]:
        path = getContextVar(path, scope)

    try:
        logging.info(tokens[0] + " "+ tokens[1] + " "+ str(node) + " "+ tokens[3]+ " " + str(path))
        new_node = serviceGraph.add_network_monitor(node, path)
        scope["new_node"] = new_node
    except Exception as ex:
        raise ex # just rethrow it for now

def move(tokens, scope):
    # move iteration_element to reconfiguration_net
    if len(tokens) < 4: # for now very basic syntax checking
        raise Exception("Malformed statement: too few arguments")
    node = tokens[1].replace("'", "")
    if node == tokens[1]:
        node = getContextVar(node, scope)
    net = tokens[3].replace("'", "")
    if net == tokens[3]:
        net = getContextVar(net, scope)

    try:
        logging.info(tokens[0]+ " " + str(node) + " "+ tokens[2]+ " " + str(net))
        serviceGraph.move(node, net)
    except Exception as ex:
        raise ex # just rethrow it for now

def getContextVar(key, scope):
    # gets the value of the given variable in the first scope where it finds it, starting from the
    # innermost one
    if key in scope:
        return scope[key]
    if "outerScope" in scope:
        return getContextVar(key, scope["outerScope"])
    raise Exception(f"Can't find this variable in the program stack: {key}")

def setContextVar(key, scope, newValue):
    # sets the value of the given variable in the first scope where it finds it, starting from the
    # innermost one
    if key in scope:
        scope[key] = newValue
        return newValue
    if "outerScope" in scope:
        return setContextVar(key, scope["outerScope"], newValue)
    raise Exception(f"Can't find this variable in the program stack: {key}")

def evaluateRow(riga, scope):
    # this function is called on each row of the "program" and for each one executes
    # the relative construct "if/iterate_on" or calls the given function

    # tokens = nltk.word_tokenize(riga) # this splits also on '
    tokens = riga.split(" ")

    if tokens[0] == "list_paths":
        # sets the variable path_list in the scope. path_list will contain a list of paths
        logging.info("Now calling list_paths function ...")
        list_paths(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "find_node":
        # sets found_node to the name of the first node found on the path, if one is not found set to None
        # sets found to true or false
        logging.info("Now calling find_node function ...")
        find_node(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "add_node":
        # adds a node of the specified type between two nodes
        # sets the new_node variable on the scope
        logging.info("Now calling add_node function ...")
        add_node(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "add_firewall":
        # takes a node name and a path as input
        # puts a firewall right behind the node on that path
        # example giving as input node2 and the following path as a list in the same order as displayed:
        # node1 <---> node2 <---> node3 <---> node4
        # node1 <---> node2 <---> firewall <---> node3 <---> node4
        logging.info("Now calling add_firewall function ...")
        add_firewall(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "add_honeypot":
        # adds a new host with the given vulnerability in the honey net
        logging.info("Now calling add_honeypot function ...")
        add_honeypot(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "add_network_monitor":
        # takes a node name and a path as input
        # puts a network monitor node right behind the node on that path
        # example giving as input node2 and the following path as a list in the same order as displayed:
        # node1 <---> node2 <---> node3 <---> node4
        # node1 <---> node2 <---> netowork_monitor <---> node3 <---> node4
        logging.info("Now calling add_network_monitor function ...")
        add_network_monitor(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "move":
        logging.info("Now calling move function ...")
        move(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "shutdown":
        # takes a node name as input and shuts it down
        logging.info("Now calling shutdown function ...")
        shutdown(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "isolate":
        # takes a node name as input and disconnect all interfaces
        logging.info("Now calling isolate function ...")
        isolate(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "add_filtering_rules":
        # adds the rule to the rule list of the specified firewall node
        # doesn't set anything on the scope
        logging.info("Now calling add_filtering_rules function ...")
        add_filtering_rules(tokens, scope)
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "iterate_on": # "nested iterate" works
        logging.info("Now going into iterate_on construct ...")
        iterateScope = {
            "some_variable_for_iterate_scope": 0,
            "outerScope": scope
        }
        scope["blockStartCursor"] = getContextVar("rowCursor", scope) + 1
        nameOfListToIterateOn = tokens[1]
        for item in getContextVar(nameOfListToIterateOn, scope):
            iterateScope["iteration_element"] = item
            iterateScope["rowCursor"] = scope["blockStartCursor"]
            interpet(statements=sentences, lenght=len(sentences), scope=iterateScope)
            scope["rowCursor"] = iterateScope["rowCursor"]
        return 0
    elif tokens[0] == "if": # "nested if else" not tested but should work
        logging.info("Now going into if/else construct ...")
        ifScope = {
            "some_variable_for_if_scope": 0,
            "outerScope": scope,
            "rowCursor": getContextVar("rowCursor", scope)
        }
        # compute "if" condition, considering potential "not" keyword
        condition = (not getContextVar(tokens[2], scope)) if tokens[1] == "not" else getContextVar(tokens[1], scope)

        if(condition):
            # condition true -> take if branch
            # execute normally with interpret. when encountering else or endif will return here and set outer rowCursor to after the endif
            ifScope["rowCursor"] = getContextVar("rowCursor", scope) + 1
            interpet(statements=sentences, lenght=len(sentences), scope=ifScope)
            for index, item in enumerate(sentences[ifScope["rowCursor"]-1:], start=ifScope["rowCursor"]-1):
                if item == "endif":
                    scope["rowCursor"] = index + 1
                    break
        else:
            # condition false -> take else branch
            # jump to after else (set rowcursor) or endif and continue normally with interpret, then when ecnountering endif will return here and set outer rowCursor to after the endif
            for index, item in enumerate(sentences[ifScope["rowCursor"]:], start=ifScope["rowCursor"]):
                if item == "else":
                    ifScope["rowCursor"] = index + 1
                    interpet(statements=sentences, lenght=len(sentences), scope=ifScope)
                    for index2, item2 in enumerate(sentences[ifScope["rowCursor"]:], start=ifScope["rowCursor"]):
                        if item2 == "endif":
                            scope["rowCursor"] = index2 + 1
                            return 0
                if item == "endif":
                    scope["rowCursor"] = index + 1
                    return 0
    elif tokens[0] == "enditeration": # end of iteration loop -> return to calling intrpreter
        logging.info("Exiting iteration construct")
        scope["rowCursor"] += 1
        return 1
    elif tokens[0] == "endif": # end of if block -> return to calling interpreter
        logging.info("Exiting if/else construct")
        scope["rowCursor"] += 1
        return 1
    elif tokens[0] == "else": # end of if branch -> return to calling interpreter
        logging.info("Now exiting if/else construct")
        scope["rowCursor"] += 1
        return 1
    elif tokens[0] == "testIf": # just print testIf
        print("testIf executed")
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "testElse": # just print testElse
        print("testElse executed")
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "invertCondizioneTest":
        if getContextVar("condizioneTest", scope):
            setContextVar("condizioneTest", scope, False)
        else:
            setContextVar("condizioneTest", scope, True)
        print("invertCondizioneTest executed")
        print(scope["iteration_element"])
        scope["rowCursor"] += 1
        return 0
    elif tokens[0] == "actionThatDoesNothing":
        print("actionThatDoesNothing executed")
        print(scope["iteration_element"])
        scope["rowCursor"] += 1
        return 0
    else:
        logging.info(f"Unrecognized statement: {tokens[0]}")
        raise Exception(f"Unrecognized statement: {tokens[0]}")

def interpet(statements, lenght, scope):
    # This is the interpreter, that loops on the program rows and calls the evaluateRow for evaluating them
    # It can be recursevely called from language constructs, for example an iteration statement calls it on
    # each loop, and once the iteration block is completely executed control is returned to the outer
    # interpreter (see break call inside the {if result == 1} ).
    # On each nested construct a new interpret is called.

    # serviceGraph.refreshAndSave(serviceGraph.sgraph)

    logging.info("Starting interpreter parsing ...")
    while(getContextVar("rowCursor", scope) < lenght):
        result = evaluateRow(statements[getContextVar("rowCursor", scope)], scope)
        if result == 1: # for ending iteration and if blocks
            break

global_scope = {
  "path_list": None,
  "listTest1": [1, 2, 3],
  "listTest2": ["a", "b", "c"],
  "condizioneTest": False,
  "attack_payload": "{...PAYLOAD...}",
  "source": "1.1.1.1",
  "rowCursor": 0,
  "varProva1": 10,
  "varProva2": "prova",
  "impacted_host_ip": "10.1.0.10",
# "impacted_nodes": ["10.1.0.10", "10.1.0.11"], # integrity information, if any
  "vulnerable_nodes": [], # nodes vulnerable to the threat, if any
  "services_involved": [],
  "threat_type": "", # { “new zero-day found” | “attack in progress detected” | “malware detected” | … } # type of the threat
#   "risk_level": 1..3 // high-level risk assessment of threat for vulnerable/impacted nodes, use for weighed response
#   "threat_details": {
#     identifier: { “emotet” | “ddos” }
#     protocol_used_by_c&c: “telnet” | …
#     attack_payload: { ... }
#     port_used: { … }
#     source: { “internet” | set of ip addresses } // could it be also geographical ?
#   }
}
logging.info("Set initial gloabl scope")


threat_repository={
    "malware": {
        "Cridex": {
            "rules": [{
                "level": 4,
                "ip_addresses": ["43.234.233.2"],
                "proto": "tcp",
                "port": 443
            },{
                "level": 4,
                "ip_addresses": ["43.234.233.2"],
                "proto": "tcp",
                "port": 443
            }],
            "suggested_recipe": "filter_ip_port_recipe"
        },
        "Zeus": {
            "rules":[{
                "level": 7,
                "ip_addresses": ["43.234.233.2"],
                "proto": "tcp",
                "port": 443,
                "payload": "xx"
            },{
                "level": 7,
                "ip_addresses": ["43.234.233.2"],
                "proto": "tcp",
                "port": 443,
                "payload": "xx"
            }],
            "suggested_recipe": "filter_payload_recipe"
        },
        "command_control": {
            "suggested_recipe": "filter_payload_recipe"
        }





    }

}

def selectRecipe():

    while(True):
        print(
            "1) Filter payload on impacted node\n"
            "2) Filter ip and port on impacted node\n"
            "3) Monitor traffic on impacted node\n"
            "4) Put impacted nodes into reconfiguration net\n"
            "5) Add honeypot for each impacted node\n"
            "6) Shutdown impacted nodes\n"
            "7) Isolate impacted nodes"
        )

        choice = int(input("Select the recipe to apply: \n>>> "))
        if choice == 1:
            return filter_payload_recipe
        elif choice == 2:
            return filter_ip_port_recipe
        elif choice == 3:
            return monitor_traffic_recipe
        elif choice == 4:
            return put_into_reconfiguration_recipe
        elif choice == 5:
            return add_honeypot_recipe
        elif choice == 6:
            return shutdown_recipe
        elif choice == 7:
            return isolate_recipe
        else:
            print("You tried :)")

def remediateMalware():
    if threatName == "command_control":
        logging.info("Generic command and control threat detected, apply countermeasures ...")
        global_scope["impacted_nodes"] = [impacted_host_ip]
        global_scope["rules_level_4"] = {
                "level": 4,
                "ipDst": impacted_host_ip,
                "portDst": impacted_host_port,
                "ipSrc": "*",
                "portSrc": "*",
            }

        suggestedRecipe = threat_repository[threatType][threatName]["suggested_recipe"]
        print(f"Recommended recipe for the threat: \n{recipeRepository[suggestedRecipe]['description']} with parameters: ")
        print(f"Impacted host ip: {impacted_host_ip} \nImpacted host port: {impacted_host_port} \nAttacker ip: *\nAttacker port: *")
    elif threatName in threat_repository[threatType]:
        logging.info("Threat found in the repository, applying specific countermeasures ...")
        firewallRules = threat_repository[threatType][threatName]["rules"]
        global_scope["rules_level_7"] = [rule for rule in firewallRules if rule["level"] == 7]
        global_scope["rules_level_4"] = [rule for rule in firewallRules if rule["level"] == 4]
        global_scope["impacted_nodes"] = [impacted_host_ip]
        for rule in global_scope["rules_level_4"]:
            rule["dstIP"] = impacted_host_ip
            rule["dstPort"] = impacted_host_port

        suggestedRecipe = threat_repository[threatType][threatName]["suggested_recipe"]
        print(f"Recommended recipe for the threat: \n{recipeRepository[suggestedRecipe]['description']} with parameters: ")
        print(f"Impacted host ip: {impacted_host_ip} \nImpacted host port: {impacted_host_port} \nAttacker ip: {attacker_ip}\nAttacker port: {attacker_port}")
    else:
        logging.info("Threat not found in the repository, applying specific countermeasures ...")
        global_scope["impacted_nodes"] = [impacted_host_ip]
        suggestedRecipe = "isolate_recipe"
        print(f"Recommended recipe for the threat: \n{recipeRepository[suggestedRecipe]['description']} with parameters: ")
        print(f"Impacted host ip: {impacted_host_ip} \nImpacted host port: {impacted_host_port} \nAttacker ip: {attacker_ip}\nAttacker port: {attacker_port}")

if __name__ == "__main__":

    while 1:
        prompt = "Insert threat details with this format \n(threat type) (threat name) (impacted host ip) (impacted host port)\n>>> "
        inputData = input(prompt).split()

    ########## CLI input examples ##########
    # malware command_control 10.1.0.10 22 12.12.12.12 8080
    # malware Cridex 10.1.0.10 22 12.12.12.12 8080
    # malware Zeus 10.1.0.10 22 12.12.12.12 8080
    ########################################

        threatType = inputData[0]
        threatName = inputData[1]
        impacted_host_ip = inputData[2]
        impacted_host_port = inputData[3]
        attacker_ip = inputData[4]
        attacker_port = inputData[5]

        global_scope["threat_type"] = threatType # malware
        global_scope["threat_name"] = threatName # command_control / Cridex / Zeus
        global_scope["impacted_host_ip"] = impacted_host_ip # 10.1.0.10
        global_scope["impacted_host_port"] = impacted_host_port # 22

        if (threatType == "malware"):
            logging.info("Remediating malware ...")
            remediateMalware()
        else:
            logging.info("Unsopperted threat remediation ...")
            print("Only malware remediation is supported at the moment!")

        recipe = selectRecipe()
        #todo logging host ip and port after showing suggesterecipe

        print("The recipe being applied is: ")
        
        rawSentences = nltk.line_tokenize(recipe)
        logging.info("Tokenized per line")
        sentences = []
        for sentence in rawSentences:
            sentences.append(sentence.strip()) # to remove trailing and leading extra white spaces
        logging.info("Removed trailing and leading whitespaces")

        # This call to interpret() triggers the start of the program
        logging.info("Launching interpreter ...")
        interpet(statements=sentences, lenght=len(sentences), scope=global_scope)

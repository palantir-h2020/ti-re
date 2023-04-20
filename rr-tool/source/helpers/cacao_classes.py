import uuid
import yaml


def getNewID():
    if not hasattr(getNewID, "counter"):
        getNewID.counter = -1
    getNewID.counter += 1
    config = 0
    if (config == 1):
        return uuid.uuid4()
    else:
        return getNewID.counter


class Step():

    acceptedParameters = ["name", "description", "external_references", "delay", "timeout", "step_variables",
    "owner", "on_completion", "on_success", "on_failure", "step_extensions"]

    def __init__(self, step_type=None, **kwargs) -> None:
        self._properties = {}
        self._properties["type"] = step_type
        self.step_id = f"step--uuid{str(getNewID())}"
        for key, value in kwargs.items():
            self.setProperty(key, value)

    def setProperty(self, key, value):
        if key in self.acceptedParameters:
            self._properties[key] = value
        else:
            raise TypeError(f"{key} is not a permitted Step object property in the CACAO 1.1 OASIS standard")

    def __getitem__(self, item):
        return self._properties[item]

    def __setitem__(self, key, value):
        self._properties[key] = value

    def toDict(self) -> dict:
        return {**self._properties}

    def setOnCompletionStep(self, step_id):
        self.setProperty("on_completion", step_id)

    def addVariable(self, name, value, variable_type = "undefined", description="nothing", constant = False):
        if "step_variables" not in self._properties:
            self._properties["step_variables"] = {}
        self["step_variables"][name] =  {
            "type": variable_type,
            "description": description,
            "value": value,
            "constant": constant
        }

    def addExtension(self, extensionID: str, extension: dict):
        if "step_extensions" not in self._properties:
            self._properties["step_extensions"] = {}
        self["step_extensions"][extensionID] = extension

    def setOnSuccessStep(self):
        pass

    def setOnFailureStep(self):
        pass

    def __str__(self):
        return str({self.step_id: self._properties})

    def __repr__(self):
        return f"Step(id: {self.step_id}, {self._properties})"


class StartStep(Step):

    def __init__(self, **kwargs) -> None:
        super().__init__("start", **kwargs)

class EndStep(Step):

    def __init__(self, **kwargs) -> None:
        super().__init__("end", **kwargs)

class SingleActionStep(Step):

    def __init__(self, *commands, **kwargs) -> None:
        super().__init__("single", **kwargs)
        self.in_args = []
        self.out_args = []
        self["commands"] = list(commands)

    def addCommands(self, *args):
        if self["commands"] is None:
            self["commands"] = []
        for command in args:
            self["commands"].append(command)

    def addOutArg(self, *args):
        for command in args:
            self.out_args.append(command)

    def addInArg(self, *args):
        for command in args:
            self.in_args.append(command)

    def toDict(self):
        newDict = {**self._properties}
        newDict["commands"] = [x.toDict() for x in newDict["commands"]]
        newDict["in_args"] = self.in_args
        newDict["out_args"] = self.out_args
        return newDict

class PlaybookStep(Step):

    def __init__(self, playbook_id=None, **kwargs) -> None:
        super().__init__("playbook", **kwargs)
        self["playbook_id"] = playbook_id

class ParallelStep(Step):

    def __init__(self, next_steps=None, **kwargs) -> None:
        super().__init__("parallel", **kwargs)
        self["next_steps"] = next_steps

class IfConditionStep(Step):

    acceptedParameters = ["condition", "on_true", "on_false", "on_completion"] #todo solve inheritance of acceptedParamters from Step class

    def __init__(self, condition=None, on_true=None, on_false=None, **kwargs) -> None:
        super().__init__("if-condition", **kwargs)
        self["condition"] = condition
        self["on_true"] = on_true
        self["on_false"] = on_false

    def setOnTrueStep(self, step_id):
        self.setProperty("on_true", step_id)

    def setOnFalseStep(self, step_id):
        self.setProperty("on_false", step_id)

    def setCondition(self, condition):
        self.setProperty("condition", condition)

class WhileConditionStep(Step):

    acceptedParameters = ["condition", "on_true", "on_false"] #todo solve inheritance of acceptedParamters from Step class

    def __init__(self, condition=None, on_true=None, on_false=None, **kwargs) -> None:
        super().__init__("while-condition", **kwargs)
        self["condition"] = condition
        self["on_true"] = on_true
        self["on_false"] = on_false

    def setOnTrueStep(self, step_id):
        self.setProperty("on_true", step_id)

    def setOnFalseStep(self, step_id):
        self.setProperty("on_false", step_id)

    def setCondition(self, condition):
        self.setProperty("condition", condition)


class SwitchConditionStep(Step):

    def __init__(self, switch=None, cases=None, **kwargs) -> None:
        super().__init__("switch-condition", **kwargs)
        self["switch"] = switch
        self["cases"] = cases


class Command():

    acceptedParameters = ["type", "command", "command_b64", "version"]

    def __init__(self, **kwargs) -> None:
        self._properties = {}
        for key, value in kwargs.items():
            self.setProperty(key, value)

    def setProperty(self, key, value):
        if key in self.acceptedParameters:
            self._properties[key] = value
        else:
            raise TypeError(f"{key} is not a permitted Step object property in the CACAO 1.1 OASIS standard")

    def toDict(self) -> dict:
        return {**self._properties}

    def __str__(self):
        return str(self._properties)

    def __repr__(self):
        return f"Command({self._properties['command']})"


class Playbook:

    acceptedParameters = ["description", "revoked", "valid_from", "valid_until", "derived_from", "priority", "severity", "impact",
    "industry_sectors", "labels", "external_references", "features", "markings", "playbook_variables", "workflow_start",
    "workflow_exception", "workflow", "targets", "extension_definition"]

    def __init__(self, playbook_type=None, name=None,
                                    playbook_types=None,
                                    playbook_id=f"playbook--uuid{str(getNewID())}",
                                    created_by="Org",
                                    created="2022",
                                    modified="2022",
                                    spec_version="1.1",
                                    **kwargs) -> None:

        self._properties = {}
        self._properties["type"] = playbook_type
        self._properties["spec_version"] = spec_version
        self._properties["id"] = playbook_id
        self._properties["name"] = name
        self._properties["playbook_types"] = playbook_types
        self._properties["playbook_variables"] = {}
        self._properties["created_by"] = created_by
        self._properties["created"] = created
        self._properties["modified"] = modified
        self.workflow = []
        for key, value in kwargs.items():
            self.setProperty(key, value)

    def setProperty(self, key, value):
        if key in self.acceptedParameters:
            self._properties[key] = value
        else:
            raise TypeError(f"{key} is not a permitted Playbook object property in the CACAO 1.1 OASIS standard")

    def __getitem__(self, item):
        if item in self._properties:
            return self._properties[item]
        else:
            return None

    def __setitem__(self, key, value):
        self._properties[key] = value

    def addSteps(self, *args: Step):
        if self["workflow_start"] is None:
            self["workflow_start"] = args[0].step_id
        for step in args:
            self.workflow.append(step)

    def addExtensionDefinition(self, name, extension_type=None, description=None, created_by=None, schema=None, version=None):
        if "extension_definitions" not in self._properties:
            self._properties["extension_definitions"] = {}
        newId=f"extension-definition--uuid{str(getNewID())}"
        self._properties["extension_definitions"][newId] = {
            "type": extension_type,
            "name": name,
            "description": description,
            "created_by": created_by,
            "schema": schema,
            "version": version
        }
        return newId

    def addGlobalVariable(self, name,
                                value,
                                variable_type,
                                constant=None,
                                description=None,
                                external=None):
        self._properties["playbook_variables"][f"$${name}$$"] = {"type": variable_type,
                                                                    "description": description,
                                                                    "value": value,
                                                                    "constant": constant,
                                                                    "external": external}

    def toDict(self) -> dict:
        newDict: dict = {**self._properties}
        newDict["workflow"] = {}
        for step in self.workflow:
            newDict["workflow"][step.step_id] = step.toDict()
        return newDict

    def __str__(self):
        return str(self._properties)


if __name__ == "__main__":

    command1 = Command(type="manual", command="Get IOC from threat feed")
    command2 = Command(type="manual", command="Open firewall console and add 1.2.3.4 to the firewall blocking policy")
    command3 = Command(type="manual", command="Get IOC from threat feed")

    step1 = SingleActionStep(command1, command2, command3)
    step2 = SingleActionStep(command2)
    step3 = SingleActionStep(command1)

    playbook = Playbook(playbook_type="playbook",
                            name="firstPlaybook",
                            playbook_types=["remediation"])

    playbook.addSteps(step1, step2, step3)

    playdict = playbook.toDict()
    #pprint(playbook.toDict())

    print(yaml.dump(playdict, default_flow_style=False, sort_keys=False))

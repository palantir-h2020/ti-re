# Recommendation and Remediation (RR) tool

The Recommendation and Remediation (RR) tool is able to react to threat alerts received from the TCAM component by deducing and applying a set of mitigation actions, for example reconfiguring security controls already present in the network or deploying new ones. The RR choices are based on the content of its Knowledge Base (KB), contained in the kb folder, which comprises the following sub-folders:

- recipes: contains a set of recipes, i.e. sets of high-level mitigation actions, that may be employed to react to a threat;
- security_controls: contains a set of descriptions of security controls (e.g. L4 firewalls) supported by the RR tools, that may be reconfigured for threat mitigation purposes;
- threats: contains a set of descriptions of threats, organized with one folder for each threat category, specifying in particular the recipes that may be followed to properly mitigate the specific threat.

The RR tool is deployed as a Kubernetes pod, and can be launched on any Kubernetes cluster by executing the rr_tool_clean_start.sh script. The execution may be customized by launching the aforementioned script with the following flags:

- o: enables (with value 1) or disables (with value 0) the connection to the Security Orchestrator component for the automatic reconfiguration of security controls;
- f: if set (with value 1), existing rules added to security controls by previous executions of the RR tool will be purged at startup;
- d: if set (with value 1), the RR will communicate on specific Kafka topics used for testing purposes;
- b: can be used to specify a specific repository branch to be downloaded and executed (by default the latest version of the master branch is downloaded);
- t: MANDATORY, the number of the tenant (i.e. the Kubernetes namespace) where the RR is being started;
- z: can be used to set a custom tenant ID to be used in the calls to the Security Orchestrator (by default the t flag value is used);
- v: can be used to specify the VIM ID that must be inserted in the calls to the Security Orchestrator (mandatory to achieve automatic reconfiguration of security controls)
- i: can be used to specify the IP of the Security Orchestrator.


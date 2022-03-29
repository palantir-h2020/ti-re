from rr_tool import RRTool


def main():
    ####################### CLI input examples ########################
    # malware unknown 10.1.0.10 22 12.12.12.12                #
    # malware Cridex 10.1.0.10 22 12.12.12.12                         #
    # malware Zeus 10.1.0.10 22 12.12.12.12                           #
    # malware Neptune 10.1.0.10 22 12.12.12.12                        #
    ###################################################################

    env = { "ENABLE_DEFAULT_L4_FILTERING_RULE_ATTACKER_PORT" : "1"}
    remediator = RRTool(env=env)
    remediator.folderInput("netflow_alerts", "netflow")



if __name__ == "__main__":
    main()

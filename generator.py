#!/usr/bin/python3

import os,sys, json
from datetime import datetime
import random, hashlib, psutil

# global parameters - feel free to change it if you want to
FOLDER_NAME = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
PROJECT_FOLDER = os.path.join(os.getcwd(),FOLDER_NAME)
WAZUH_LAST_OCTET = "137"
PROJECT_TARGETS = {}

def octet_extract(subnet_addr):
    val = subnet_addr.split('.')[0] + "." + subnet_addr.split('.')[1] + "." + subnet_addr.split('.')[2]

    return val

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    res = []

    for interface_name, interface_addresses in interfaces.items():
        res.append(interface_name)
    
    return res

def netmask_extract(subnet_addr):
    val = subnet_addr.split("/")
    if val[1] == "8":
        return "255.0.0.0"
    elif val[1] == "16":
        return "255.255.0.0"
    elif val[1] == "24":
        return "255.255.255.0"
    elif val[1] == "30":
        return "255.255.255.252"

def router_construct(jsonConfig):
    team1 = jsonConfig['TEAM1_DEETS']
    team2 = jsonConfig['TEAM2_DEETS']
    others = jsonConfig['OTHER_DEETS']

    router_path = PROJECT_FOLDER + "/koth_router"

    vagrantfile_router_old = open(router_path+"/Vagrantfile", "r")
    vagrantfile_router_new = open(router_path+"/Vagrantfile.new", "w")

    for line in vagrantfile_router_old:
        data = ""

        # this is to define the router interfaces

        if "TARGET_GW_T1" in line:
            gw = octet_extract(team1['TARGET_SUBNET']) + ".1"
            netmask = netmask_extract(team1['TARGET_SUBNET'])
            data = "  config.vm.network \"public_network\", bridge: \""+get_network_interfaces()[1]+"\", ip: \""+gw+"\", netmask: \""+netmask+"\"\n"
            
        elif "TARGET_GW_T2" in line:
            gw = octet_extract(team2['TARGET_SUBNET']) + ".1"
            netmask = netmask_extract(team2['TARGET_SUBNET'])
            data = "  config.vm.network \"public_network\", bridge: \""+get_network_interfaces()[1]+"\", ip: \""+gw+"\", netmask: \""+netmask+"\"\n"

        elif "TARGET_GW_SB" in line:
            gw = octet_extract(others['SCOREBOARD_SUBNET']) + ".1"
            netmask = netmask_extract(others['SCOREBOARD_SUBNET'])
            data = "  config.vm.network \"public_network\", bridge: \""+get_network_interfaces()[1]+"\", ip: \""+gw+"\", netmask: \""+netmask+"\"\n"

        elif "INTF_T1" in line:
            data = "    v.customize [\"modifyvm\",:id, \"--nic2\",\"intnet\",\"--intnet2\",\""+team1['TARGET_ADAPTER']+"\"]\n"

        elif "INTF_T2" in line:
            data = "    v.customize [\"modifyvm\",:id, \"--nic3\",\"intnet\",\"--intnet3\",\""+team2['TARGET_ADAPTER']+"\"]\n"

        elif "INTF_SB" in line:
            data = "    v.customize [\"modifyvm\",:id, \"--nic4\",\"intnet\",\"--intnet4\",\""+others['SCOREBOARD_ADAPTER']+"\"]\n"

        # this is to define the zerotier networks
        elif "ATTACKER_SUBNET_ZT_TEAM1" in line:
            data = "sudo zerotier-cli join "+ team1['ATTACKER_SUBNET_ZT'] + "\n"
        
        elif "ATTACKER_SUBNET_ZT_TEAM2" in line:
            data = "sudo zerotier-cli join " + team2['ATTACKER_SUBNET_ZT'] + "\n"

        elif "DEFENDER_SUBNET_ZT_TEAM1" in line:
            data = "sudo zerotier-cli join " + team1['DEFENDER_SUBNET_ZT'] + "\n"

        elif "DEFENDER_SUBNET_ZT_TEAM2" in line:
            data = "sudo zerotier-cli join " + team2['DEFENDER_SUBNET_ZT'] + "\n"

        elif "GENERAL_NETWORK_ROUTES" in line:
            data = "sudo iptables -A INPUT -s " + team1['TARGET_SUBNET'] + " -j ACCEPT"
            data += "\nsudo iptables -A INPUT -s " + team2['TARGET_SUBNET'] + " -j ACCEPT"
            data += "\nsudo iptables -A INPUT -s " + others['SCOREBOARD_SUBNET'] + " -j ACCEPT"
        
        elif "TARGET_APP_ROUTES" in line:
            atk_ports = others['PORTS']['attack']
            data = ""
            for atk_port in atk_ports:
                port_num = atk_port.strip() # to remove whitespaces
                data += "\nsudo iptables -A INPUT -p tcp -s " + team1['ATTACKER_SUBNET'] + " -d " + team2['TARGET_SUBNET'] + " --dport "+ port_num + " -j ACCEPT"
                data += "\nsudo iptables -A INPUT -p tcp -s " + team2['ATTACKER_SUBNET'] + " -d " + team1['TARGET_SUBNET'] + " --dport "+ port_num + " -j ACCEPT"

        elif "DEFENSE_ROUTES" in line:
            def_ports = others['PORTS']['defense']
            data = ""
            for port in def_ports:
                portnum = port.strip()
                data += "\nsudo iptables -A INPUT -p tcp -s " + team1['DEFENDER_SUBNET'] + " -d " + team1['TARGET_SUBNET'] + " --dport "+portnum+" -j ACCEPT"
                data += "\nsudo iptables -A INPUT -p tcp -s " + team2['DEFENDER_SUBNET'] + " -d " + team2['TARGET_SUBNET'] + " --dport "+portnum+" -j ACCEPT"

        elif "SCOREBOARD_ROUTES" in line:
            sb_ports = others['PORTS']['scoreboard']
            data = ""
            for port in sb_ports:
                portnum = port.strip()
                data += "\nsudo iptables -A INPUT -p tcp -s " + team1['DEFENDER_SUBNET'] + " -d " + others['SCOREBOARD_SUBNET'] + " --dport "+portnum+" -j ACCEPT"
                data += "\nsudo iptables -A INPUT -p tcp -s " + team2['DEFENDER_SUBNET'] + " -d " + others['SCOREBOARD_SUBNET'] + " --dport "+portnum+" -j ACCEPT"

        else:
            data = line

        vagrantfile_router_new.write(data)

    vagrantfile_router_old.close()
    vagrantfile_router_new.close()

    os.system("cp "+router_path+"/Vagrantfile.new "+router_path+"/Vagrantfile")
    os.system("rm -rf "+router_path+"/Vagrantfile.new")

def sb_construct(jsonConfig):
    others = jsonConfig['OTHER_DEETS']
    team1 = jsonConfig['TEAM1_DEETS']
    team2 = jsonConfig['TEAM2_DEETS']

    sb_path = PROJECT_FOLDER + "/koth_sb"

    vagrantfile_sb_old = open(sb_path+"/Vagrantfile", "r")
    vagrantfile_sb_new = open(sb_path+"/Vagrantfile.new", "w")

    for line in vagrantfile_sb_old:
        data = ""
        ip_addr = octet_extract(others['SCOREBOARD_SUBNET']) + ".2"
        netmask = netmask_extract(others['SCOREBOARD_SUBNET'])

        if "SB_IP" in line:

            data = "  config.vm.network \"public_network\", bridge: \""+get_network_interfaces()[1]+"\", ip: \""+ip_addr+"\", netmask: \""+netmask+"\"\n"
        
        elif "SB_ROUTES" in line:
            data = "route add -net "+ team1['TARGET_SUBNET'] + " gw " + octet_extract(others['SCOREBOARD_SUBNET']) + ".1"
            data += "\nroute add -net "+ team1['DEFENDER_SUBNET'] + " gw " + octet_extract(others['SCOREBOARD_SUBNET']) + ".1"
            data += "\nroute add -net "+ team2['TARGET_SUBNET'] + " gw " + octet_extract(others['SCOREBOARD_SUBNET']) + ".1"
            data += "\nroute add -net "+ team2['DEFENDER_SUBNET'] + " gw " + octet_extract(others['SCOREBOARD_SUBNET']) + ".1"

        elif "INTF_SB" in line:
            data = "    vb.customize [\"modifyvm\",:id, \"--nic2\",\"intnet\",\"--intnet2\",\""+others['SCOREBOARD_ADAPTER']+"\"]\n"  

        else:
            data = line  

        vagrantfile_sb_new.write(data)

    vagrantfile_sb_old.close()
    vagrantfile_sb_new.close()

    os.system("cp "+sb_path+"/Vagrantfile.new "+sb_path+"/Vagrantfile")
    os.system("rm -rf "+sb_path+"/Vagrantfile.new")

    propane_config(jsonConfig,PROJECT_TARGETS)

def propane_config(jsonConfig,targets):

    players = jsonConfig['OTHER_DEETS']['PLAYERS']
    propane_config_filepath = PROJECT_FOLDER + "/koth_sb/appcode/propane_config.ini"
    # modifying the targets
    f_old = open(propane_config_filepath, "r")
    f_new = open(propane_config_filepath + ".new", "w")
    for line in f_old:
        data = ""
        if "TEAMONE_TARGETS" in line:
            for key in targets.keys():
                if key.split('-')[0] == "team1":
                    data += key + " = " + targets[key] + "\n"
        
        elif "TEAMTWO_TARGETS" in line:
            for key in targets.keys():
                if key.split('-')[0] == "team2":
                    data += key + " = " + targets[key] + "\n"

        elif "TEAMONE_TARGETPORTS" in line:
            for key in targets.keys():
                if key.split('-'[0]) == "team1":
                    data += key + " = 80\n"

        elif "TEAMTWO_TARGETPORTS" in line:
            for key in targets.keys():
                if key.split('-'[0]) == "team2":
                    data += key + " = 80\n"
        
        elif "WHITELIST_USERS" in line:
            data += "users = " + ','.join(players)
    
        else:
            data = line

        f_new.write(data)

    f_old.close()
    f_new.close()

    os.system("cp "+propane_config_filepath+".new " + propane_config_filepath)
    os.system("rm -rf "+propane_config_filepath+".new")

def wazuh_construct(jsonConfig, teamNo):
    
    srcTeam = {}
    destTeam = {}

    if teamNo == 1:
        srcTeam = jsonConfig['TEAM1_DEETS']
        destTeam = jsonConfig['TEAM2_DEETS']
    else:
        srcTeam = jsonConfig['TEAM2_DEETS']
        destTeam = jsonConfig['TEAM1_DEETS']
    
    others = jsonConfig['OTHER_DEETS']
    
    attk_3octet = octet_extract(srcTeam['ATTACKER_SUBNET'])
    def_3octet = octet_extract(srcTeam['DEFENDER_SUBNET'])
    target_3octet = octet_extract(srcTeam['TARGET_SUBNET'])

    wazuh_path = PROJECT_FOLDER + "/team" + str(teamNo) + "/koth_wazuh"
    # Vagrantfile configuration for the wazuh machine
    vagrantfile_wazuh_old = open(wazuh_path+"/Vagrantfile", "r")
    vagrantfile_wazuh_new = open(wazuh_path+"/Vagrantfile.new", "w")

    for line in vagrantfile_wazuh_old:
        if "ROUTES_HERE" in line:
            vagrantfile_wazuh_new.write("route add -net "+srcTeam['TARGET_SUBNET']+ " gw "+ def_3octet + ".1\n")
            vagrantfile_wazuh_new.write("route add -net "+others['SCOREBOARD_SUBNET']+ " gw "+ def_3octet + ".1\n")
        elif "TEAM_NAME" in line:
            vagrantfile_wazuh_new.write("  config.vm.hostname = \"wazuh-team"+str(teamNo)+"\"\n")
        elif "ZT_DEFENSE_NETWORK" in line:
            vagrantfile_wazuh_new.write("echo \"Joining Defender Network Team "+str(teamNo)+"! Authorise it in 2 minutes.\"\n")
            vagrantfile_wazuh_new.write("sudo zerotier-cli join "+srcTeam['DEFENDER_SUBNET_ZT']+"\n")
            vagrantfile_wazuh_new.write("sleep 120\n")
            
        else:
            vagrantfile_wazuh_new.write(line)
            
    vagrantfile_wazuh_old.close()
    vagrantfile_wazuh_new.close()

    # only uncomment this once it is working
    os.system("cp "+wazuh_path+"/Vagrantfile.new "+wazuh_path+"/Vagrantfile")
    os.system("rm -rf "+wazuh_path+"/Vagrantfile.new")

def team_construct(jsonConfig, teamNo):
    teamLabel = "team" + str(teamNo)
    team_path = PROJECT_FOLDER + "/" + teamLabel
    # clone the assets folder to a team folder
    os.system("cp -r " + PROJECT_FOLDER + "/assets "+team_path)
    
    srcTeam = {}
    destTeam = {}

    if teamNo == 1:
        srcTeam = jsonConfig['TEAM1_DEETS']
        destTeam = jsonConfig['TEAM2_DEETS']
    else:
        srcTeam = jsonConfig['TEAM2_DEETS']
        destTeam = jsonConfig['TEAM1_DEETS']
    
    # srcTeam => the team that we are currently focusing the efforts of making the templates on
    # destTeam => opposing team
    
    attk_3octet = octet_extract(srcTeam['ATTACKER_SUBNET'])
    def_3octet = octet_extract(srcTeam['DEFENDER_SUBNET'])
    target_3octet = octet_extract(srcTeam['TARGET_SUBNET'])

    # configuration for the 4 app subnets
    app_folders = os.listdir(team_path + "/targets")
    
    # generation of SSH key
    privkey_loc = PROJECT_FOLDER + "/" + teamLabel + "-key"
    pubkey_loc = privkey_loc + ".pub"
    os.system("ssh-keygen -t rsa -N '' -f "+privkey_loc)

    # to store the public key for wazuh
    os.system("cp " + pubkey_loc + " " + team_path + "/koth_wazuh/artifacts/key.pub")

    for i in range(len(app_folders)):
        app_path = team_path + "/targets/" + app_folders[i]
        
        # copying SSH public keys
        os.system("cp "+ pubkey_loc + " " + app_path + "/artifacts/key.pub")

        vagrantfile_old = open(app_path+"/Vagrantfile","r")
        vagrantfile_new = open(app_path+"/Vagrantfile.new","w")

        for line in vagrantfile_old:
            data = ""
            if "APP_ADDRESS_HERE" in line:
                app_addr = octet_extract(srcTeam['TARGET_SUBNET']) + "." + str(random.randint(100,250))
                PROJECT_TARGETS[teamLabel + '-' + app_folders[i]] = app_addr
                netmask = netmask_extract(srcTeam['TARGET_SUBNET'])
                data = "  config.vm.network \"public_network\", bridge: \""+get_network_interfaces()[1]+"\", ip: \""+app_addr+"\", netmask: \""+netmask+"\"\n"
            
            elif "ROUTES_HERE" in line: 
                # routes for the team's apps should only be for the opponent's attacker network + the team's defense network
                data = "route add -net "+destTeam['ATTACKER_SUBNET']+ " gw "+ target_3octet + ".1\n"
                data += "route add -net "+jsonConfig['OTHER_DEETS']['SCOREBOARD_SUBNET']+ " gw "+ target_3octet + ".1\n"
                data += "route add -net "+srcTeam['DEFENDER_SUBNET']+ " gw "+ target_3octet + ".1\n"
            
            elif "TEAM_INTF" in line:
                target_adapter = srcTeam['TARGET_ADAPTER']
                data = "    vb.customize [\"modifyvm\", :id, \"--nic2\", \"intnet\", \"--intnet2\", \""+target_adapter+"\"]\n"

            else:
                data = line

            vagrantfile_new.write(data)

        vagrantfile_old.close()
        vagrantfile_new.close()

        # only uncomment this once it is working
        os.system("cp "+app_path+"/Vagrantfile.new "+app_path+"/Vagrantfile")
        os.system("rm -rf "+app_path+"/Vagrantfile.new")


        # Updating snort conf for the apps
        snort_conf_old = open(app_path+"/artifacts/snort.conf","r")
        snort_conf_new = open(app_path+"/artifacts/snort.conf.new","w")
        

        for line in snort_conf_old:
            data = ""
            if "APP_ADDRESS_HERE/32" in line:
                app_addr = PROJECT_TARGETS[teamLabel + '-' + app_folders[i]]
                data = "var HOME_NET "+app_addr+"/32\n"
            else:
                data = line
            snort_conf_new.write(data)

        snort_conf_old.close()
        snort_conf_new.close()

        # only uncomment this once it is working
        os.system("cp "+app_path+"/artifacts/snort.conf.new "+app_path+"/artifacts/snort.conf")
        os.system("rm -rf "+app_path+"/artifacts/snort.conf.new")

        snort_debconf_old = ""
        snort_debconf_new = ""

        snort_debconf_old = open(app_path+"/artifacts/snort.debian.conf","r")
        snort_debconf_new = open(app_path+"/artifacts/snort.debian.conf.new","w")
        
        for line in snort_debconf_old:
            if "DEBIAN_SNORT_HOME_NET=\"APP_ADDRESS_HERE/32\"" in line:
                app_addr = PROJECT_TARGETS[teamLabel + '-' + app_folders[i]]
                snort_debconf_new.write("DEBIAN_SNORT_HOME_NET=\""+app_addr+"/32\"\n")
            else:
                snort_debconf_new.write(line)
        
        snort_debconf_old.close()
        snort_debconf_new.close()

        # only uncomment this once it is working
        os.system("cp "+app_path+"/artifacts/snort.debian.conf.new "+app_path+"/artifacts/snort.debian.conf")
        os.system("rm -rf "+app_path+"/artifacts/snort.debian.conf.new")

        dockerfile_old = ""
        dockerfile_new = ""

        dockerfile_old = open(app_path+"/Dockerfile","r")
        dockerfile_new = open(app_path+"/Dockerfile.new","w")
    
        for line in dockerfile_old:
            if "WAZUH_INSTALL" in line:
                wazuh_addr = def_3octet + "." + WAZUH_LAST_OCTET
                wazuh_agent_name = "team"+str(teamNo)+"-"+app_folders[i]
                dockerfile_new.write("RUN wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.1-1_amd64.deb -O /root/wazuh-agent.deb && WAZUH_MANAGER='"+wazuh_addr+"' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='"+wazuh_agent_name+"' dpkg -i /root/wazuh-agent.deb\n")
            else:
                dockerfile_new.write(line)
        
        dockerfile_old.close()
        dockerfile_new.close()

        # only uncomment this once it is working
    
        os.system("cp "+app_path+"/Dockerfile.new "+app_path+"/Dockerfile")
        os.system("rm -rf "+app_path+"/Dockerfile.new")

    # zip the keys
    zip_passwd = hashlib.sha256(random.randbytes(random.randint(100,254))).hexdigest()
    zip_filename = teamLabel + "-key.7z"
    zip_path = team_path + "/" + zip_filename
    os.system("7z a -p" + zip_passwd + " " +zip_path+" "+privkey_loc)

    passwd_file = open(PROJECT_FOLDER + "/passwords.txt","a")
    passwd_file.write("Team " + str(teamNo) + " Key ZIP File Password: " + zip_passwd + "\n")
    passwd_file.close()

    # public keys + zipped private keys inside the /keys folder in the scoreboard
    os.system("mv "+pubkey_loc+ " " +PROJECT_FOLDER+"/koth_sb/appcode/template/keys/")
    os.system("mv "+zip_path+ " " +PROJECT_FOLDER+"/koth_sb/appcode/template/keys/")
    os.system("rm -rf "+privkey_loc)

    # construct the wazuh instance once the app boxes are done
    wazuh_construct(jsonConfig, teamNo)

if len(sys.argv) == 2:
    configfile = open(sys.argv[1],"r")
    configs = json.load(configfile)
    configfile.close()

    # copy template folder into project foler.
    os.system("cp -r template/ "+PROJECT_FOLDER)

    # make the necessary configuration file
    team_construct(configs, 1)
    team_construct(configs, 2)
    router_construct(configs)
    sb_construct(configs)

    # delete assets folder
    os.system("rm -rf "+PROJECT_FOLDER+"/assets")

    # once all of these things work, then zip it into a file (followed by deleting the project folder)
    # [decided not to zip it because eventually this git clone repo needs to be done in the server deploying the environment]
    # os.system("7z a "+FOLDER_NAME+".7z "+PROJECT_FOLDER)
    # os.system("rm -rf "+PROJECT_FOLDER)

else:
    print("Usage: generator.py path_to_config_file")

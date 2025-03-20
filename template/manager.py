#!/usr/bin/python3

import os, sys
from subprocess import Popen, PIPE
# function of the manager script is to either start or destroy the whole vagrant environment

CURRENT_CWD = os.getcwd()
BOX_PATHS = {}


def fetch_boxpaths():
    BOX_PATHS['router'] = CURRENT_CWD + "/koth_router"
    BOX_PATHS['scoreboard'] = CURRENT_CWD + "/koth_sb"

    # team 1's path
    team_path = CURRENT_CWD + "/team1"

    wazuh_path = team_path + "/koth_wazuh"
    BOX_PATHS["team1-wazuh"] = wazuh_path

    targets_path = team_path + "/targets"
    target_list = os.listdir(targets_path)

    for target in target_list:
        BOX_PATHS["team1-"+target] = targets_path + "/" + target
    
    # team 2's path
    team_path = CURRENT_CWD + "/team2"

    wazuh_path = team_path + "/koth_wazuh"
    BOX_PATHS["team2-wazuh"] = wazuh_path

    targets_path = team_path + "/targets"
    target_list = os.listdir(targets_path)

    for target in target_list:
        BOX_PATHS["team2-"+target] = targets_path + "/" + target

def destroy_box(boxPath):
    os.system("VAGRANT_CWD="+boxPath+" vagrant destroy -f")

def start_box(boxPath):
    os.system("VAGRANT_CWD="+boxPath+" vagrant up")

def ssh_box(boxPath):
    os.system("VAGRANT_CWD="+boxPath+" vagrant ssh")

def start_infraboxes():
    # start up the router
    print("[oooo] Starting up the core router!")
    router_path = CURRENT_CWD + "/koth_router"
    start_box(router_path)

    # start up the scoreboard
    print("[oooo] Starting up the scoreboard!")
    sb_path = CURRENT_CWD + "/koth_sb"
    start_box(sb_path)

def destroy_infraboxes():
    # start up the router
    print("[xxxx] Destroying the core router!")
    router_path = CURRENT_CWD + "/koth_router"
    destroy_box(router_path)

    # start up the scoreboard
    print("[xxxx] Destroying the scoreboard!")
    sb_path = CURRENT_CWD + "/koth_sb"
    destroy_box(sb_path)


def start_teamboxes(teamNo):

    team_path = CURRENT_CWD + "/team" + str(teamNo)
    
    # start up wazuh instance
    wazuh_path = team_path + "/koth_wazuh"
    start_box(wazuh_path)

    # start up the 4 app boxes
    targets_path = team_path + "/targets"
    target_list = os.listdir(targets_path)

    for target in target_list:
        print("[oooo] Starting up "+ target + "!")
        start_box(targets_path + "/" + target)

def destroy_teamboxes(teamNo):

    team_path = CURRENT_CWD + "/team" + str(teamNo)
    
    # start up wazuh instance
    wazuh_path = team_path + "/koth_wazuh"
    destroy_box(wazuh_path)

    # start up the 4 app boxes
    targets_path = team_path + "/targets"
    target_list = os.listdir(targets_path)

    for target in target_list:
        print("[oooo] Destroying "+ target + "!")
        destroy_box(targets_path + "/" + target)

fetch_boxpaths()

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Usage")
    print("=====")
    print("python3 manager.py startall -> starts the entire environment.")
    print("python3 manager.py endall -> destroys the entire environment.")
    print("python3 manager.py start box_name -> starts a specific cyber range asset.")
    print("python3 manager.py end box_name -> destroys a specific cyber range asset.")
    print("python3 manager.py ssh box_name -> establishes a SSH session on the specified cyber range asset.")
    print("\nList of available boxes in this project:")
    for boxNames in BOX_PATHS.keys():
        print("- "+boxNames)
else:
    if len(sys.argv) == 2:
        if sys.argv[1] == "startall":
            print("[*] Powering up the core infra boxes..")
            start_infraboxes()
            print("[*] Powering up team 1's boxes..")
            start_teamboxes(1)
            print("[*] Powering up team 2's boxes..")
            start_teamboxes(2)
            
        elif sys.argv[1] == "endall":
            print("[*] Destroying team 1's boxes..")
            destroy_teamboxes(1)
            print("[*] Destroying team 2's boxes..")
            destroy_teamboxes(2)
            print("[*] Destroying the core infra boxes..")
            destroy_infraboxes()
   
    elif len(sys.argv) == 3:
        if sys.argv[1] == "start":
            if sys.argv[2] in BOX_PATHS.keys():
                start_box(BOX_PATHS[sys.argv[2]])
            else:
                print("Invalid box specified. Please refer to the list!")
        elif sys.argv[1] == "end":
            if sys.argv[2] in BOX_PATHS.keys():
                destroy_box(BOX_PATHS[sys.argv[2]])
            else:
                print("Invalid box specified. Please refer to the list!")

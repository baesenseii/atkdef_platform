# Attack-Defense Training Platform
If you want to set up a simple attack-and-defense exercise between two teams, don't have any money to generate cloud environments but you do have an abudance of hardware at zero cost (okay, maybe the cost of the bills), then this is the tool for you :)
## Pre-Requisites
### Hardware Requirements
- A laptop/PC/server with minimally 32GB of RAM (16GB might work but you may only be able to spin off ONE target). Ideal is 48GB RAM :)
- Big hard disk space (minimally 500GB or even 1TB, HDD or SSD doesn't really matter unless you're considering performance)
- Electricity (of course)
### Software Requirements
- Laptop/PC/Server will need to be in Linux (because it is far more superior in range management + CLI leetness). This platform was tested on an Ubuntu Server 24.04 host.
- In addition, the following programs need to be installed:
    - VirtualBox (note that we won't even be using the GUI, so you can use non-GUI OSes like Ubuntu Server)
    - Vagrant
    - Git
### Other Requirements
This deployment heavily relies on using ZeroTier (https://www.zerotier.com), which is a global private network PaaS that allows linking of devices over private networks. The size is entirely up to you, but for this exercise I designed it for a typical 5v5 engagement (in which the free ZeroTier account limit of 25 devices will suffice).
## Installation
1. If you have not done so, sign up for a ZeroTier account. Once you do, log in and create 4 ZeroTier networks (kindly take note of the subnet addresses configured within each ZeroTier network):
    - Team 1
        - Attacker Network
        - Defender Network
    - Team 2
        - Attacker Network
        - Defender Network
2. Edit the config.txt file to set the 4 ZeroTier Networks and their respective subnet addresses.
3. Go to the target_catalogs folder and copy the targets you want to try out into the template/assets/targets folder. DO NOT FORGET TO DELETE THE 'example' FOLDER.
4. Once all is settled, run the following command within the git folder:
```
python3 generator.py config.txt
```
This will generate a project folder (name is a datetime stamp) with all the modified configurations that is in accordance to the configurations stated.
5. Launch the ZeroTier Administration Portal on a web browser. Then, run the following commands to start deploying the platform:
```
cd project_folder_name; python3 manager.py startall
```
6. The first infrastructure component that will be started up is the corerouter, which links all the networks from both ZeroTier and internal instances. When you see a message like this:
```
Joining Attacker Network Team 1! Authorise it in 2 minutes.
```
Go to the ZeroTier Administration Portal and perform the following task:
- Go to the affected ZeroTier network, you will see a device that is newly joined into the network (marked with a cross).
- Edit the device and set the following properties:
    - Set it to 'Authorized'
    - Set the IP address to the subnet configured with the last octet to be .1 (e.g if the configured ZeroTier subnet is 192.168.193.0/24, the corresponding IP address will be 192.168.193.1)
7. Note that you will have to do Step 6 for the following boxes (so keep an eye out for the 'Authorise it in 2 minutes' message):
    - Team 1's Wazuh SIEM (team1-koth_wazuh) => last octet is .137
    - Team 2's Wazuh SIEM (team2-koth_wazuh) => last octet is .137
    - KOTH Scoreboard (koth_sb) => last octet is .2
## Client Device Configuration
For this, it is best that the user's device utilises a Virtual Machine (preferably Kali Linux) to connect to the range network. To install ZeroTier in Kali Linux, run the following command:
```
curl -s https://install.zerotier.com | sudo bash
```
Once you have installed your ZeroTier application, firstly you need to decide if your machine is an 'Attacker' machine or a 'Defender' machine. Once you have decided that, follow the steps in accordance to your choice:
### Attacker Setup
Obtain the ZeroTier ID of the attacker network that you are joining, and run this command:
```
sudo zerotier-cli join zerotier_id_network_here 
```
Do note that after joining, you will need the ZeroTier Administrator to authorise you before you can get the IP address. Once that is done, you will need to find out the following information:
- Gateway IP address of the attacker's network that you are joining via ZeroTier
- The subnet of your opponent team's targets
Once you have figured this out, modify the command and run it in Terminal:
```
route add -net subnet_opponent_targets gw gateway_ip_attacker_network
```
### Defender Setup
Obtain the ZeroTier ID of the defender network that you are joining, and run this command:
```
sudo zerotier-cli join zerotier_id_network_here 
```
Do note that after joining, you will need the ZeroTier Administrator to authorise you before you can get the IP address. Once that is done, you will need to find out the following information:
- Gateway IP address of the defender's network that you are joining via ZeroTier.
- The scoreboard subnet

Once you have figured this out, modify the command and run it in Terminal:
```
route add -net subnet_scoreboard gw gateway_ip_defender_network
```

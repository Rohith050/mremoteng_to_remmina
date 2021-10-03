# mremoteng_to_remmina

Can be used to convert mremoteng xml backups to remmina files.
Handles RDP, SSH, VNC

Doesnt really handle Telnet connections as Remmina doesnt support Telnet . Telnet is possible with Simple terminal but I dont like using telnet and neither should you. Anyways , option is given to convert telnet sessions to ssh sessions while converting.

Please note that mremoteng has a gazillion options per connection. Only options needed for basic connectivity are converted. Rest of them are set to default. Pease check skeleton variables in remmina_mremoteng_convertor.py file.

Mremoteng group structure will be preserved in remmina.

**Requirements:**

I used python3.8 for development and testing. But it might most probably work with lower python3 versions also. Please do not use python2.
Added requirements.txt file with the needed modules.
Please use 'python3 -m pip install -r requirements.txt' to install the needed modules.

You would need a couple of keys for decrypting mremoteng passwords and encrypting remmina password.

**Remmina secret:** Ideally located in ~/.config/remmina/remmina.pref file. This file location might change depending on how you installed remmina. 
You can probably do a 'find / -iname remmina.pref 2>/dev/null' to search in all the folders. In this file, there will be a field called secret=xxxxxxxxxx. The xxxxxxxxx would be the remmina key.

**Mremoteng secret:** Optional. Defaulted to "mR3m"

Originally written for my personal usage. Sharing here as it might help others. Might not address all scenarios but hopefully script will get you started.

**Usage:**

remmina_mremoteng_convertor.py -f mremoteng_backup.xml -rk remmina_key -mk mremoteng_key

script will create a folder called 'remmina_converted' and stores all the newly created remmina files in this.
Copy these files into the remmina data folder where all the session files are stored. This path is ideally '~/.local/share/remmina/'. This folder location might change depending on how you installed remmina. Please check https://gitlab.com/Remmina/Remmina/-/issues/2178 for more info. 
Or else you can open remmina, go to preferences -> options -> Remmina data folder. Copy the converted files to this folder and restart remmina. Converted session files should show up.

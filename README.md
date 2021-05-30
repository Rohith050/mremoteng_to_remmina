# mremoteng_to_remmina

Can be used to convert mremoteng xml backups to remmina files.
Handles RDP, SSH, VNC

Doesnt really handle Telnet connections as Remmina doesnt support Telnet . Telnet is possible with Simple terminal but I dont like using telnet and neither should you. Anyways , option is give to convert telnet sessions to ssh sessions while converting.

Please note that mremoteng has a gazillion options per connection. Only options needed for basic connectivity are converted. Rest of them are set to default. Pease check skeleton variables in remmina_mremoteng_convertor.py file.

Mremoteng group structure will be preserved in remmina.

You would need a couple of keys for decrypting mremoteng passwords and encrypting remmina password.

**Remmina secret:** Ideally located in ~/.config/remmina/remmina.pref file

**Mremoteng secret:** Optional. Defaulted to "mR3m"

Originally written for my personal usage. Sharing here as it might help others. Might not address all scenarios but hopefully script will get you started.

**Usage:**

remmina_mremoteng_convertor.py -f mremoteng_backup.xml -rk remmina_key -mk mremoteng_key

script will create a folder called 'remmina_converted' and stores all the newly created remmina files in this.
  

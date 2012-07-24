#!/usr/bin/python
import ConfigParser
import sys
import os
import datetime
import netifaces
import subnetMath

#add_to_* functions simply append passed information to the buffers
#that are built independently for the creation of ipsec.conf
def add_to_setup(option, value):
  config_setup += "\t"+option+"="+value+"\n"

def add_to_default(option, value):
  global conn_default
  conn_default += "\t"+option+"="+value+"\n"

def add_to_subnet_extrusion(option, value):
  global conn_subnet_extrusion
  conn_subnet_extrusion += "\t"+option+"="+value+"\n"

#this following block of endless prompts, defaults, and parsing is intended to provide a relatively
#sane and easy way for someone to enter the network information without touching the config files
#note: some of this is redundant wrt to the initialization scripts, but this is intended more for reconfig
#than initial, plus I wrote it first.
def guide_human(newcfg):
  answer = ""
  
  newcfg.write("\n[local]\n")
  while(answer.lower() != "cloud" and answer.lower() != "client"):
    answer = raw_input("\nIs this machine in the cloud, or at the client's location (cloud/client)? ")
  if answer.lower() == "cloud":
    newcfg.write("target = cloud\n")
  else:
    newcfg.write("target = client\n")
  
  newcfg.write("\n[cloud]\n")
  print "\nPlease enter the cloud machine's internal IP and subnet or netmask."
  print "You may specify the internal IP and subnet/netmask in the form of (1) 1.1.1.1/24 or (2) 1.1.1.1 and 255.255.255.0"
  while(answer != "1" and answer != "1"):
    answer = raw_input("\tWhich one do you want to enter (1/2)? ")
    if answer == "1":
      answer = raw_input("\t\tPlease enter the internal IP and subnet combination: ")
      newcfg.write("internal-ip = " + answer+"\n")
      break
    else:
      answer = raw_input("\t\tPlease enter the internal IP (ex: 10.0.0.1): ")
      newcfg.write("internal-ip = " + answer+"\n")
      answer = raw_input("\t\tPlease enter the internal netmask (ex: 255.255.0.0): ")
      newcfg.write("internal-netmask = " + answer+"\n")
      break
  answer = raw_input("Please enter the cloud machine's external IP: ")
  newcfg.write("external-ip = " + answer + "\n")
  
  newcfg.write("\n[client]\n")
  print "\nPlease enter the client machine's internal IP and subnet or netmask."
  print "You may specify the internal IP and subnet/netmask in the form of (1) 1.1.1.1/24 or (2) 1.1.1.1 and 255.255.255.0"
  while(answer != "1" and answer != "1"):
    answer = raw_input("\tWhich one do you want to enter (1/2)? ")
    if answer == "1":
      answer = raw_input("\t\tPlease enter the internal IP and subnet combination: ")
      newcfg.write("internal-ip = " + answer+"\n")
      break
    else:
      answer = raw_input("\t\tPlease enter the internal IP (ex: 10.0.0.1): ")
      newcfg.write("internal-ip = " + answer+"\n")
      answer = raw_input("\t\tPlease enter the internal netmask (ex: 255.255.0.0): ")
      newcfg.write("internal-netmask = " + answer+"\n")
      break
  answer = raw_input("Please enter the client machine's external IP: ")
  newcfg.write("external-ip = " + answer + "\n")
  
  newcfg.write("\n[global]\n")
  answer = raw_input("How do you want to specify the IPsec network interface? (AUTOMATIC/manual): ")
  if answer.lower() == "manual":
    answer = raw_input("\tEnter the network device for the IPsec interface: ")
    newcfg.write("ipsec-interface = " + answer+"\n")
  else:
    newcfg.write("ipsec-interface = automatic\n")
    
  while answer.lower() not in ["rsa","psk"]:
    answer = raw_input("\nPlease chose an encryption method. PSK is simpler, RSA is more secure. (PSK/RSA): ")
  if answer.lower() == "rsa":
    newcfg.write("authby = rsa\n")
    answer = raw_input("\tHow do you wish to enter the client machine public key (key/file/AUTOMATIC)? ")
    if answer.lower() == "key":
      answer = raw_input("\t\tPlease copy in the client's public RSA key: ")
      newcfg.write("clientkey = " + answer.rstrip("\n") + "\n")
    elif answer.lower() == "file":
      answer = raw_input("\t\tPlease copy in the location of the client's public RSA keyfile: ")
      newcfg.write("clientkey-file = " + answer.rstrip("\n") + "\n")
    else:
      print "\t\tThe key will automatically be generated, and the new public"
      print "\t\tkey will be printed to screen and saved to file"
      newcfg.write("clientkey = automatic\n")
    answer = raw_input("\tHow do you wish to enter the cloud machine public key (key/file/AUTOMATIC)? ")
    if answer.lower() == "key":
      answer = raw_input("\t\tPlease copy in the cloud machine's public RSA key: ")
      newcfg.write("cloudkey = " + answer.rstrip("\n") + "\n")
    elif answer.lower() == "file":
      answer = raw_input("\t\tPlease copy in the location of the cloud machine's public RSA keyfile: ")
      newcfg.write("cloudkey-file = " + answer.rstrip("\n") + "\n")
    else:
      print "\t\tThe key will automatically be generated, and the new public"
      print "\t\tkey will be printed to screen and saved to file"
      newcfg.write("cloudkey = automatic\n")  
  else:
    newcfg.write("authby=psk\n")
    answer = raw_input("\tPlease enter the Pre-Shared Key: ")
    newcfg.write("psk-secret = " + answer.rstrip("\n") + "\n")
  print "\nFurther advanced options may be found in the generated config\n" 
  
  newcfg.write("version = 2.0\nprotostack = klips\noe = disabled\nnat-traversal = disabled\ntype = tunnel\n")
  
  print "Your configuration is generated, but not parsed. Run the command again to set up ipsec with the selected options"
 
#Contains parsing, error handling, and general workings 
def main():
  global config_setup
  global conn_default
  global conn_subnet_extrusion

  ipsec_secrets_file = "/etc/ipsec.secrets"
  ipsec_config_file = "/etc/ipsec.conf"
  rng_started = 0
  pubkey = ""

  config_setup += "config setup\n"
  conn_default += "conn %default\n"
  conn_subnet_extrusion += "conn subnet-extrusion\n"
  
  parser = ConfigParser.RawConfigParser()
  time = datetime.date.today()

  if len(sys.argv) > 2:
    print "Usage: " + sys.argv[0] + " [config]"
    return
  elif len(sys.argv) < 2:
    config_name = "config.cfg"
  else:
    config_name = sys.argv[1]
  
  try:
    with open(config_name) as f:
      print config_name+" found, loading...\n"
      new_cfg = 0
  except IOError:
    print "No config specified or found..."
    answer = raw_input("\tOK to create new (Y/n)? ")
    if answer.lower() != 'n':
      new_cfg = 1
    else:
      print answer
      print "Bailing out."
      quit()
  if new_cfg == 1:
    cfg = open(config_name,'w')
    cfg.write("\n#\t---Automatically generated by "+sys.argv[0].lstrip("./")+" on "+time.isoformat()+"---\t#\n")
    guide_human(cfg)
    quit()
  elif new_cfg == 0:
    parser.read(config_name)
    current_target = parser.get('local','target')

    #cloud
    if parser.has_option('cloud','internal-netmask'): #otherwise it's all combined
        cloudNet = subnetMath.Subnet(parser.get('cloud','internal-ip'),parser.get('cloud','internal-netmask'))
    else:
        cloudNet = subnetMath.Subnet(parser.get('cloud','internal-ip'))        

    cloud_ext_ip = parser.get('cloud','external-ip')
    #add what we've got to the config buffer
    add_to_subnet_extrusion("leftsourceip","".join(map(str,cloudNet.toIPaddress())))  #ugh. new feature time for subnetMath.
    add_to_subnet_extrusion("leftsubnet","".join(map(str,cloudNet.toSubnetZeroed()))) #openswan likes to have the insignificant bits zeroed in ipsec.conf
    add_to_subnet_extrusion("left",cloud_ext_ip)
    
    #client
    if parser.has_option('client','internal-netmask'): #same as above
        clientNet = subnetMath.Subnet(parser.get('client','internal-ip'),parser.get('client','internal-netmask'))
    else:
        clientNet = subnetMath.Subnet(parser.get('client','internal-ip'))

    client_ext_ip = parser.get('client','external-ip') # can't guess this
    #add what we've got to the config buffer
    add_to_subnet_extrusion("rightsourceip","".join(map(str,clientNet.toIPaddress())))
    add_to_subnet_extrusion("rightsubnet","".join(map(str,clientNet.toSubnetZeroed())))
    add_to_subnet_extrusion("right",client_ext_ip)
    
    #globals
    if parser.has_option('global','ipsec-interface'):
      ipsec_interface = parser.get('global','ipsec-interface')
    else:
      ipsec_interface = "automatic"
    if ipsec_interface.lower() == "automatic":
      interfaces = netifaces.interfaces()
      for interface in interfaces:
        try:
          iface_ip = netifaces.ifaddresses(interface)[2][0]['addr']
          #Could be faster, but this avoids some collisions
          if ((iface_ip == client_ext_ip) and (current_target.lower() == "client") and (interface.find("ipsec") == -1)):
            ipsec_interface = interface
            break
          elif ((iface_ip == cloud_ext_ip) and (current_target.lower() == "cloud") and (interface.find("ipsec") == -1)):
            ipsec_interface = interface
            break
        except ValueError:
          print "[info]: " + interface + " is unavailable"
    
    add_to_setup("interfaces","\"ipsec0="+ipsec_interface+"\"") 
      
    if parser.has_option('global','version'): 
      ipsec_version = parser.get('global','version')
    else:
      ipsec_version = "2.0" #we're just going to write this first, so save it.
      
    if parser.has_option('global','protostack'):
      ipsec_protostack = parser.get('global','protostack')
    else:
      ipsec_protostack = "klips"
    add_to_setup("protostack",ipsec_protostack)
    
    if parser.has_option('global','opportunistic-encryption'):
      if parser.get('global','opportunistic-encryption').lower() == "enabled":
        ipsec_oe = "on"
      else:
        ipsec_oe = "off"      
    else:
      ipsec_oe = "off"
    add_to_setup("oe",ipsec_oe)
      
    if parser.has_option('global','type'):  
      ipsec_type = parser.get('global','type')
    else:
      ipsec_type = "tunnel"
    add_to_subnet_extrusion("type",ipsec_type)
    
    ipsec_auth = parser.get('global','authby') #they can't avoid this one.
    if ipsec_auth.lower() == "rsa":
      #cloud = ipsec "left", client = ipsec "right"
      try:
        cloud_rsa_key = parser.get('global','cloudkey')
      except ConfigParser.NoOptionError: #use file
        cloud_rsa_file = open(parser.get('global','cloudkey-file'))
        cloud_rsa_key = cloud_rsa_file.readline()
        cloud_rsa_file.close()
      try:
        client_rsa_key = parser.get('global','clientkey')
      except ConfigParser.NoOptionError: #use file
        client_rsa_file = open(parser.get('global','clientkey-file'))
        client_rsa_key = client_rsa_file.readline()
        client_rsa_file.close()
	  #determine if we're low on entropy - if this is running on a normal VM w/o hardware entropy sources,
	  #that's probably a yes
      if (cloud_rsa_key.lower() == "automatic" and current_target.lower() == "cloud") or (client_rsa_key.lower() == "automatic" and current_target.lower() == "client"):
        entropy_avail = open("/proc/sys/kernel/random/entropy_avail",'r')
        if int(entropy_avail.read()) < 800:
          answer = raw_input("Entropy low. Start rngd daemon (Y/n)? ")
          if answer.lower() != "n":
            os.system("service rng-tools start")
            rng_started = 1
          else:
            print "Warning: Key generation (if required) may take a very long time"
            rng_started = 0
        entropy_avail.close()
      #automatic RSA key generation for cloud endpoint
	  #Pretty explicit: uses the OS shell to call the ipsec new key function, 
	  #displays the private key, and saves it in ipsec.conf
      if cloud_rsa_key.lower() == "automatic" and current_target.lower() == "cloud":
        print "\nGenerating new cloud RSA key..."
        os.system("ipsec newhostkey --output "+ipsec_secrets_file) 
        print "Copy this to the client config. Careful with newlines.\n"#possibly have this create a cfg for the client script?
        key = open(""+ipsec_secrets_file,'r')
        while pubkey.find("pubkey=") == -1:
          pubkey = key.readline()
        key.close()
        print "cloudkey="+pubkey[9:]
        cloud_rsa_key = pubkey[9:].rstrip('\n')
        if client_rsa_key.lower() == "automatic":
          client_rsa_key = "[CLIENT PUBKEY HERE]"
        key = open("cloud.pubkey",'w')
        key.write(pubkey[9:])
        key.close()
        print "Cloud public key saved in cloud.pubkey.\n"
        
      elif client_rsa_key.lower() == "automatic" and current_target.lower() == "client":
        print "\nGenerating new client RSA key..."
        os.system("ipsec newhostkey --output "+ipsec_secrets_file) 
        print "Copy this to the cloud config. Careful with newlines.\n" #possibly have this create a cfg for the cloud script?
        key = open(""+ipsec_secrets_file,'r')
        while pubkey.find("pubkey=") == -1:
          pubkey = key.readline()
        key.close()
        print "clientkey="+pubkey[9:]
        client_rsa_key = pubkey[9:].rstrip('\n')
        if cloud_rsa_key.lower() == "automatic":
          cloud_rsa_key = "[CLOUD PUBKEY HERE]"
        key = open("client.pubkey",'w')
        key.write(pubkey[9:])
        key.close()
        print "Client public key saved in client.pubkey.\n"
        
      else:
        print "Using existing keys."
        if current_target.lower() == "cloud" and client_rsa_key.lower() == "automatic":
          client_rsa_key = "[CLIENT PUBKEY HERE]"
        if current_target.lower() == "client" and cloud_rsa_key.lower() == "automatic":
          cloud_rsa_key = "[CLOUD PUBKEY HERE]"
      if rng_started == 1:
        os.system("service rng-tools stop")
        print ""
      #After that mess, let's write the things
      add_to_config(cconn_default,"authby",ipsec_auth)
      add_to_subnet_extrusion("leftrsasigkey",cloud_rsa_key)
      add_to_config(conn_subnet-extrustion,"rightrsasigkey",client_rsa_key)
    elif ipsec_auth.lower() == "psk":
      ipsec_psk = parser.get('global','psk-secret')
      ipsec_auth = "secret"
      secrets = open(ipsec_secrets_file,'w')
      secrets.write(cloud_ext_ip + " " + client_ext_ip + " : PSK \"" + ipsec_psk+"\"\n")
      secrets.close() 
      add_to_default("authby",ipsec_auth)
    else:
      print ipsec_auth + " is not a valid method of authentication."
      quit()
      
    #Cisco ASA endpoint support - Force allowed encryption methods
    #This could easily be refactored to allow further customization of the encryption methods
	#for now, let's leave these as exclusive to ASA endpoint situations, as it's more secure
	#to let openswan negotiate its own preferential methods.
	#This could also easily be modified for future proprietary/third party endpoints, using the ASA as an example.
    if parser.has_option('cloud','cisco-asa'):
      if parser.get('cloud','cisco-asa').lower() == "yes":
        ipsec_auth = "psk" #force this
        if parser.has_option('global','ike-method'):
          ipsec_ike = parser.get('global','ike-method')
        else:
          ipsec_ike = "3des-sha1-modp1024" #triple DES encryption, SHA1 hash, group2 DH
        add_to_default("ike",ipsec_ike) 
        
        if parser.has_option('global','phase2algorithm'):
          ipsec_phase2alg = parser.get('global','phase2algorithm')
        else:
          ipsec_phase2alg = "3des-sha1"
        add_to_default("phase2alg",ipsec_phase2alg)  
                    
        if parser.has_option('global','keylife'):
          ipsec_keylife = parser.get('global','keylife')
        else:
          ipsec_keylife = "86400s"
        add_to_default("keylife",ipsec_keylife)
        
        #always!
        add_to_default("pfs","no")
        add_to_default("keyexchange","ike")
        add_to_default("phase2","esp")
	#support for configuring a client with SHI hosting the ASA (unlikely, but portable)
    if parser.has_option('client','cisco-asa'):
      if parser.get('client','cisco-asa').lower() == "yes":
        ipsec_auth = "psk" #force this
        if parser.has_option('global','ike-method'):
          ipsec_ike = parser.get('global','ike-method')
        else:
          ipsec_ike = "3des-sha1-modp1024" #triple DES encryption, SHA1 hash, group2 DH
        add_to_default("ike",ipsec_ike) 
          
        if parser.has_option('global','phase2algorithm'):
          ipsec_phase2alg = parser.get('global','phase2algorithm')
        else:
          ipsec_phase2alg = "3des-sha1"
        add_to_default("phase2alg",ipsec_phase2alg)  
          
        if parser.has_option('global','keylife'):
          ipsec_keylife = parser.get('global','keylife')
        else:
          ipsec_keylife = "86400s"
        add_to_default("keylife",ipsec_keylife)
          
        #always!
        add_to_default("pfs","no")
        add_to_default("keyexchange","ike")
        add_to_default("phase2","esp")
    #We want this tunnel to start automatically, always
    add_to_subnet_extrusion("auto","start")
    
    
    print "Writing "+ipsec_config_file
    ipsec_conf = open(ipsec_config_file,'w')

    ipsec_conf.write("version "+ipsec_version+"\n")

    ipsec_conf.write(config_setup+"\n\n")

    ipsec_conf.write(conn_default+"\n")

    ipsec_conf.write(conn_subnet_extrusion+"\n")
    
    ipsec_conf.write("\n#\t---Automatically generated by "+sys.argv[0].lstrip("./")+" on "+time.isoformat()+"---\t#\n")
    
    ipsec_conf.close()
    
if __name__ == '__main__':
  # Globals for config construction
  config_setup = ""
  conn_default = ""
  conn_subnet_extrusion = ""

  main()

  
'''
TODO:
  Compute and save routes (debian stores peresistent routes in /etc/network/interfaces
    Likewise - When running on the cloud machine, dump a client cfg?
'''

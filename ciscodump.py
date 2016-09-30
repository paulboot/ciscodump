#!/usr/bin/python

from secret import *
import logging
import paramiko
import time
import re
import os
import argparse
import pprint
import csv
import sys
from dns import resolver,reversename
from jinja2 import Environment, PackageLoader #@UnresolvedImport

#Dependencies
#sudo apt-get install python-dnspython python-jinja2 python-paramiko

# Version 1.1 (3-4-2015)
# Fixed 3850 interface gi1/0/1 matchen aan outlet file gaat niet goed
# Fixed 3850 show mac address wordt niet goed uitgelezen
# Added mac naar ip inlezen in de twee VSS cores
# Added printen ip adres en bijbehorende VLAN

# Version 1.2 (6-4-2015)
# Added plain HTML export in /var/www/export for import in Excel

# Version 1.3 (13-4-2015)
# Add more info to mac2ip for future reports
# IP reverse lookup van IP adressen gevonden in ARP tabellen

# Version 1.4 (16-4-2015)
# Veranderd show mac address commando om ook dynamische entries op te slaan

# Version 1.5 (23-11-2015)
# Eerste versie op de Ubuntu 14.04.3 LTS
# Secrets in losse file die niet in de code revisie hoort

# Version 1.6 (23-9-2016)
# Iets meer en netter debug informatie
# Aangepast dat ook user niet in priviliged mode # het script kunnen gebruiken
# Aanpasing template nu __file__ in de functie aanroep (niet getest)

# Version 1.x (x-4-2015)
# TODO Move output from test to interface dir
# TODO Generate history directory with old reports (also for exports)
# TODO Generate per SER HTML report, R-gebouw report is too slow
# TODO Add more info to mac2ip for future reports

version = "1.6 (23-11-2015) door Paul Boot"
prog = __name__
debug = True

csvpath = '/opt/ciscodump/csv'
targetsfile = 'targets-dev.csv'

templatepath = '../templates/'
templatefile = 'ciscodump-index.html'
templateexportfile = 'export-index.html'

htmlpath = '/var/www/html/test'
htmlexportpath = '/var/www/html/export'
htmlfile = 'interface-laatste.html'

#Hack, read arp tables from these routers
#routers = ['10.255.255.254', '192.168.254.254']
routers = ['10.255.255.254']

ifindex = {}
interfaces = {}
outlets = {}
plaatsen = set()
gebouwen = {}
targets = {}
ip2mac = {}
mac2ip = {}

log = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)
log.info('Start logging')

# Filtering
ansi_escape = re.compile(r'\x1B\[[^A-Za-z]*[A-Za-z]')

if debug:
    paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)

# References
# Google paramiko cisco example
# https://pynet.twb-tech.com/blog/python/paramiko-ssh-part1.html
# http://blog.timmattison.com/archives/2014/06/25/automating-cisco-switch-interactions/
# http://rtomaszewski.blogspot.nl/2012/08/problem-runing-ssh-or-scp-from-python.html

def parseargs():
    parser = argparse.ArgumentParser(prog=prog, description='Generate Cisco interface reports')

    parser.add_argument('--debug', action="store_true", default=False,
                            help='show debug info')
    parser.add_argument('--version', '-V', action='version', version='%(prog)s ' + version,
                            help='print version')
    return parser.parse_args()

def disable_paging(remote_conn):
    '''Disable paging on a Cisco router'''

    remote_conn.send("term len 0\n")
    time.sleep(1)
    output = remote_conn.recv(1000)
    
    if debug:
        print output

    return output

def exit_switch(remote_conn):
    '''Exits Cisco switch'''

    remote_conn.send("exit\n")
    time.sleep(1)
    output = remote_conn.recv(1000)
    if debug:
        print output

    return output

def get_interface_indexes(remote_conn):
    '''Get interface indexes'''

    global ifindex
    
    #boolean status
    
    #Get interfaces indexes
    #Cat4500
    #show snmp mib ifmib ifindex detail
    #Description                     ifIndex  Active  Persistent  Saved
    #-------------------------------------------------------------------------
    #
    #GigabitEthernet3/29              126    yes      enabled       yes
    #GigabitEthernet4/20              165    yes      enabled       yes
    #GigabitEthernet1/32              33     yes      enabled       yes
    #GigabitEthernet7/48              245    yes      enabled       yes
    #GigabitEthernet7/6               203    yes      enabled       yes
    #TenGigabitEthernet3/1            98     yes      enabled       yes
    #TenGigabitEthernet3/2            99     yes      enabled       yes
    
    #Cat3850
    #Description                     ifIndex  Active  Persistent  Saved
    #-------------------------------------------------------------------------
    #
    #GigabitEthernet1/0/39            41     yes      enabled       yes
    #GigabitEthernet1/1/4             54     yes      enabled       yes


    remote_conn.send("show snmp mib ifmib ifindex detail\n")

    buff = ''
    while not buff.endswith('>') and not buff.endswith('#'):
        if debug:
            print "show snmp mib ifmib ifindex detail: while loop fetching until > or #"
        time.sleep(1)
        output = remote_conn.recv(16384)
        if debug:
            print ansi_escape.sub('', output)
        buff += output
        buff = ansi_escape.sub('', buff)

    lines = buff.splitlines()
    for line in lines:
        #print line
        #searchObj = re.search( r'(\S{3,8})\s{2,3}(.{18})\s{1}(\S+)\s{2,4}(\S{1,8})\s{2,12}(\S+)\s+(\S+)\s(.+$)', line, re.M|re.I)
        searchObj = re.search( r'(GigabitEthernet|TenGigabitEthernet)(\S{3,6})\s+(\S{1,4})', line, re.M|re.I)
        if searchObj:
            if searchObj.group(1) == 'GigabitEthernet':
                interface = 'Gi' + searchObj.group(2)
            elif searchObj.group(1) == 'TenGigabitEthernet':
                interface = 'Te' + searchObj.group(2)
            else:
                log.error('In show snmp mib ifmib could not find valid interface type')
            
            value = '%0*s' % (4, searchObj.group(3))
            ifindexkey = (targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], interface)
            ifindex[ifindexkey] = value

    #print '-----show snmp mib ifmib ifindex detail--------'
    #print ifindex
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(ifindex)
    #sys.exit()
    
    #Now we know the indexes we can match the outlets if file exists for that gebouw
    outletsfile = csvpath + '/' + keytargets[1] + '.csv'
    if os.path.isfile(outletsfile):
        print 'Outletsfile gevonden %s' % outletsfile 
        read_csv_outlets(keytargets[1], outletsfile)
    else:
        print 'Outletsfile niet gevonden: %s' % outletsfile 
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(outlets)
    #sys.exit()

    return status
    
    
def read_csv_outlets(gebouw, filename):

    global outlets, ifindex

    with open(filename, 'rb') as f:
        reader = csv.DictReader(f, delimiter=';', quoting=csv.QUOTE_NONE)
        try:
            for row in reader:
                interface = 'Gi' + row['Module'] + '/' + row['Poort']
                interface2 = 'Gi' + row['Module'] + '/0/' + row['Poort']
                #If CSV does not containt Kast information assume Kast 1
                if not row.has_key('Kast'):
                    row['Kast'] = '1'
                
                ifindexkey = (row['SER'] + '-K' + row['Kast'], interface)
                ifindexkey2 = (row['SER'] + '-K' + row['Kast'], interface2)
                #print ifindexkey2
                
                if ifindex.has_key(ifindexkey):
                    key = (gebouw, row['SER'] + '-K' + row['Kast'] , ifindex[ifindexkey])
                    outlets[key] = {}
                    outlets[key]['outlet'] = row['Outlet']
                    outlets[key]['ruimte'] = row['Ruimte']
                    outlets[key]['toepassing'] = row['Toepassing']
                elif ifindex.has_key(ifindexkey2):
                    key = (gebouw, row['SER'] + '-K' + row['Kast'] , ifindex[ifindexkey2])
                    outlets[key] = {}
                    outlets[key]['outlet'] = row['Outlet']
                    outlets[key]['ruimte'] = row['Ruimte']
                    outlets[key]['toepassing'] = row['Toepassing']
        except csv.Error as e:
            sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))

def read_csv_targets(filename):
    """
    Fill targets dictionary using a csv configuration file.
    
    Format:
       Naam;Plaats;Gebouw;SER;Kast;IP;Type;Rapport;Uplink;Opmerking;port-channel;interfaces1;interfaces2
       SWA-DEL-R-TH-094;Delft;R-gebouw;TH;K1;10.20.255.94;WS-C3850-48P;true;nvt;TH (buiten H-gebouw, in augustus);209;1/4/9;
       SWA-DEL-R-TG-095;Delft;R-gebouw;TG;K1;10.20.255.95;WS-C3850-48P;true;nvt;TG (garage buiten terrein, in augustus);210;1/4/10;
       SWA-DEL-E-0A-191;Delft;R-gebouw;0E;K1;10.20.255.191;WS-C3850-48P;true;nvt;;208;1/4/8;2/4/8
       SWA-DEL-R-0A-001;Delft;R-gebouw;0A;K1;10.20.255.1;WS-C4510R+E;true;nvt;;105;1/2/5;2/2/5

    :param interfaces: string with a CSV filename
    :rtype: none
    """

    global plaatsen, gebouwen, targets
    
    log.info('Start reading router file: %s' % filename)
    with open(filename, 'rb') as f:
        reader = csv.DictReader(f, delimiter=';', quoting=csv.QUOTE_NONE)
        try:
            for row in reader:
                if row['Rapport'] == 'true':
                    plaatsen.add(row['Plaats'])
                    if gebouwen.has_key(row['Plaats']):
                        gebouwen[row['Plaats']].add(row['Gebouw'])
                    else:
                        gebouwen[row['Plaats']] = set()
                        gebouwen[row['Plaats']].add(row['Gebouw'])
                    key = (row['Plaats'],row['Gebouw'],row['Naam'])
                    targets[key] = {}
                    targets[key]['ip'] = row['IP']
                    targets[key]['ser'] = row['SER']
                    targets[key]['kast'] = row['Kast']
                    targets[key]['type'] = row['Type']
                    targets[key]['uplink'] = row['Uplink'].split(',')
        except csv.Error as e:
            sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))

def read_arp_tabels(routers):
    
    global ip2mac, mac2ip
    
    # Create instance of SSHClient object
    remote_conn_pre = paramiko.SSHClient()

    # Automatically add untrusted hosts 
    remote_conn_pre.set_missing_host_key_policy(
         paramiko.AutoAddPolicy())

    for router in routers:
        # initiate SSH connection
        #remote_conn_pre.connect(hostname, username=username, password=password)
        remote_conn_pre.connect(router, username=readonlyusername, password=readonlypassword, allow_agent=False, look_for_keys=False)

        print "SSH connection established to %s" % router

        # Use invoke_shell to establish an 'interactive session'
        remote_conn = remote_conn_pre.invoke_shell(term='dumb')
        print "Interactive SSH session established"

        # Strip the initial router prompt
        buff = ''
        while not buff.endswith('>') and not buff.endswith('#'):
            if debug:
                print "Initial login: while loop fetching until > or #"
            time.sleep(1)
            output = remote_conn.recv(16384)
            buff += output
            buff = ansi_escape.sub('', buff)
            
        # Turn off paging
        disable_paging(remote_conn)

        #Get arp entries
        # Protocol  Address          Age (min)  Hardware Addr   Type   Interface
        # Internet  10.5.0.254              -   0008.e3ff.ff20  ARPA   Vlan3184
        # Internet  10.11.2.2             114   7446.a0a6.c0fa  ARPA   Vlan1101
        # Internet  10.11.2.6             191   7446.a090.3c37  ARPA   Vlan1101
        
        remote_conn.send("show ip arp\n")
        
        buff = ''
        while not buff.endswith('>') and not buff.endswith('#'):
            if debug:
                print "show ip arp: while loop fetching until > or #"
            time.sleep(1)
            output = remote_conn.recv(16384)
            buff += output
            buff = ansi_escape.sub('', buff)

        lines = buff.splitlines()
        for line in lines:
            #print line
            searchObj = re.search( r'Internet\s+([0-9.]{7,15})\s+(\S+)\s+([a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4})\s+ARPA\s+Vlan([0-9]{1,4})', line, re.M|re.I)
            if searchObj:
                ip = searchObj.group(1)
                age = searchObj.group(2)
                mac = searchObj.group(3)
                vlan = searchObj.group(4)
                
                if not ip2mac.has_key(ip):
                    ip2mac[ip] = {}
                ip2mac[ip]['mac'] = mac
                ip2mac[ip]['age'] = age
                ip2mac[ip]['vlan'] = vlan
                
                if not mac2ip.has_key(mac):
                    mac2ip[mac] = {}
                mac2ip[mac]['ip'] = ip
                mac2ip[mac]['age'] = age
                mac2ip[mac]['vlan'] = vlan
                
                addr=reversename.from_address(ip)
                try:
                    (hostname, domain) = str(resolver.query(addr,"PTR")[0]).split('.', 1)
                    #print 'Found host %s for %s' % (hostname, ip)
                    ip2mac[ip]['hostname'] = hostname
                    mac2ip[mac]['hostname'] = hostname
                except resolver.NXDOMAIN:
                    #print 'resolver.NXDOMAIN in resolver.query for %s' % ip
                    pass
                except resolver.NoAnswer:
                    #print 'resolver.NoAnswer in resolver.query for %s' % ip
                    pass            

        #print '-----show ip arp--------'
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(ip2mac)
        #pp.pprint(mac2ip)
        
        exit_switch(remote_conn)
        remote_conn_pre.close()


def generate_html(plaatsen, gebouwen, targets, interfaces, ip2mac):
    """
    Generate HTML using the 'interfaces' dictionary.
    
    :param interfaces: dict with all interfaces params
    :rtype: none
    """
    
    global templatepath, templatefile, templateexportfile
    
    for plaats in plaatsen:
        for gebouw in gebouwen[plaats]:
            log.info('Start generating HTML in generate_html')
            #env = Environment(loader=PackageLoader('ciscodump', templatepath))
            env = Environment(loader=PackageLoader(__file__, templatepath))
            template = env.get_template(templatefile)
 
            #mkdir plaats
            if not os.path.exists(htmlpath + '/' + plaats):
                os.makedirs(htmlpath + '/' + plaats)
            #mkdir gebouw
            if not os.path.exists(htmlpath + '/' + plaats + '/' + gebouw):
                os.makedirs(htmlpath + '/' + plaats + '/' + gebouw)
            
            file = open(htmlpath + '/' + plaats + '/' + gebouw + '/' + htmlfile, 'w')
            file.write(template.render({'plaats' : plaats, 'gebouw' : gebouw, 'targets' : targets, 'interfaces' : interfaces, 'ip2mac' : ip2mac}))
            file.close()

            log.info('Start generating export file for Excel')
            template = env.get_template(templateexportfile)
            file = open(htmlexportpath + '/' + plaats + '-' + gebouw + '-' + htmlfile, 'w')
            file.write(template.render({'plaats' : plaats, 'gebouw' : gebouw, 'targets' : targets, 'interfaces' : interfaces, 'ip2mac' : ip2mac}))
            file.close()

            log.info('Done generating HTML in generate_html')
    
    return 


if __name__ == '__main__':

    args = parseargs()
    debug = args.debug

	#SKIP
    #read_arp_tabels(routers)
    #sys.exit()
    
    read_csv_targets(csvpath + '/' + targetsfile)
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(targets)
    pp.pprint(plaatsen)
    pp.pprint(gebouwen)
    
    # Create instance of SSHClient object
    remote_conn_pre = paramiko.SSHClient()

    # Automatically add untrusted hosts 
    remote_conn_pre.set_missing_host_key_policy(
         paramiko.AutoAddPolicy())

    for keytargets in targets:
        # initiate SSH connection
        #remote_conn_pre.connect(hostname, username=username, password=password)
        remote_conn_pre.connect(targets[keytargets]['ip'], username=readonlyusername, password=readonlypassword, allow_agent=False, look_for_keys=False)

        print "SSH connection established to %s" % keytargets[2]

        # Use invoke_shell to establish an 'interactive session'
        remote_conn = remote_conn_pre.invoke_shell(term='dumb')
        print "Interactive SSH session established"

        targets[keytargets]['laatstescan'] = time.strftime("%c")
        
        # Strip the initial router prompt
        buff = ''
        while not buff.endswith('>') and not buff.endswith('#'):
            if debug:
                print "Initial login: while loop fetching until > or #"
            time.sleep(1)
            output = remote_conn.recv(16384)
            if debug:
                print ansi_escape.sub('', output)
            buff += output
            buff = ansi_escape.sub('', buff)
            
        # Turn off paging
        disable_paging(remote_conn)

        # Read interface indexes from devices
        #get_interface_indexes(remote_conn)
        
        # Read interface status from devices
        #get_interface_status(remote_conn)

        # Read mac table from devices
        #get_mac_table
        #remote_conn.send("show mac address-table\n")

        # Read authetnication sessions from devices
        #get_auth_sessions
        #remote_conn.send("show authentication sessions\n")
        
        #DOUBLE REMOVE      
        #Get interfaces indexes
        #Cat4500
        #show snmp mib ifmib ifindex detail
        #Description                     ifIndex  Active  Persistent  Saved
        #-------------------------------------------------------------------------
        #
        #GigabitEthernet3/29              126    yes      enabled       yes
        #GigabitEthernet4/20              165    yes      enabled       yes
        #GigabitEthernet1/32              33     yes      enabled       yes
        #GigabitEthernet7/48              245    yes      enabled       yes
        #GigabitEthernet7/6               203    yes      enabled       yes
        #TenGigabitEthernet3/1            98     yes      enabled       yes
        #TenGigabitEthernet3/2            99     yes      enabled       yes
        
        #Cat3850
        #Description                     ifIndex  Active  Persistent  Saved
        #-------------------------------------------------------------------------
        #
        #GigabitEthernet1/0/39            41     yes      enabled       yes
        #GigabitEthernet1/1/4             54     yes      enabled       yes

        remote_conn.send("show snmp mib ifmib ifindex detail\n")

        buff = ''
        while not buff.endswith('>') and not buff.endswith('#'):
            if debug:
                print "show snmp mib ifmib ifindex detail: while loop fetching until > or #"
            time.sleep(1)
            output = remote_conn.recv(16384)
            if debug:
                print ansi_escape.sub('', output)
            buff += output
            buff = ansi_escape.sub('', buff)

        lines = buff.splitlines()
        for line in lines:
            #print line
            #searchObj = re.search( r'(\S{3,8})\s{2,3}(.{18})\s{1}(\S+)\s{2,4}(\S{1,8})\s{2,12}(\S+)\s+(\S+)\s(.+$)', line, re.M|re.I)
            searchObj = re.search( r'(GigabitEthernet|TenGigabitEthernet)(\S{3,6})\s+(\S{1,4})', line, re.M|re.I)
            if searchObj:
                if searchObj.group(1) == 'GigabitEthernet':
                    interface = 'Gi' + searchObj.group(2)
                elif searchObj.group(1) == 'TenGigabitEthernet':
                    interface = 'Te' + searchObj.group(2)
                else:
                    log.error('In show snmp mib ifmib could not find valid interface type')
                
                value = '%0*s' % (4, searchObj.group(3))
                ifindexkey = (targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], interface)
                ifindex[ifindexkey] = value

        #print '-----show snmp mib ifmib ifindex detail--------'
        #print ifindex
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(ifindex)
        #sys.exit()
        
        #Now we know the indexes we can match the outlets if file exists for that gebouw
        outletsfile = csvpath + '/' + keytargets[1] + '.csv'
        if os.path.isfile(outletsfile):
            print 'Outletsfile gevonden %s' % outletsfile 
            read_csv_outlets(keytargets[1], outletsfile)
        else:
            print 'Outletsfile niet gevonden: %s' % outletsfile 
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(outlets)
        #sys.exit()


        # Send the router a command
        ###############################
        #show interface status
        #Port      Name               Status       Vlan       Duplex  Speed Type
        #Fa1/0/1                      notconnect   1500         auto   auto 10/100BaseTX
        #Fa1/0/24                     notconnect   1500         auto   auto 10/100BaseTX
        #Gi1/0/1   => SWC-DEL-R-3B-25 connected    trunk      a-full a-1000 1000BaseLX SFP
        #Fa3/0/24  Pink Roccade Healt connected    810        a-full  a-100 10/100BaseTX
        #Gi3/0/1                      notconnect   1            auto   auto Not Present
        #Gi3/0/2                      notconnect   1            auto   auto Not Present
        #Gi1/10                       connected    2500       a-full  a-100 10/100/1000-TX
        #Gi1/11                       connected    2514       a-full  a-100 10/100/1000-TX
        #Port      Name               Status       Vlan       Duplex  Speed Type
        #Te1/1     => SWC-DEL-R-3A-25 connected    trunk        full    10G 10GBase-LRM
        #Te1/2     => SWC-DEL-R-3A-25 connected    trunk        full    10G 10GBase-LRM
        #Gi1/48    Pink Roccade Healt connected    810        a-full  a-100 10/100/1000-TX

        remote_conn.send("show interface status\n")

        buff = ''
        while not buff.endswith('>') and not buff.endswith('#'):
            if debug:
                print "show interface status: while loop fetching until > or #"
            time.sleep(1)
            output = remote_conn.recv(16384)
            if debug:
                print ansi_escape.sub('', output)
            buff += output
            buff = ansi_escape.sub('', buff)

        lines = buff.splitlines()
        for line in lines:
            #print line
            #searchObj = re.search( r'(\S{3,8})\s{2,3}(.{18})\s{1}(\S+)\s{2,4}(\S{1,8})\s{2,12}(\S+)\s+(\S+)\s(.+$)', line, re.M|re.I)
            searchObj = re.search( r'(Gi|Te)(\S{3,6})\s{2,5}(.{18})\s{1}(\S+)\s+(\S{1,5})\s+(\S+)\s+(\S+)\s(.+$)', line, re.M|re.I)
            if searchObj:
                interface = searchObj.group(1) + searchObj.group(2)
                description = searchObj.group(3)
                status = searchObj.group(4)
                vlan = searchObj.group(5)
                duplex = searchObj.group(6)
                speed = searchObj.group(7)
                type = searchObj.group(8)

                ifindexkey = ( targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], interface)
                key = (keytargets[1], targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], ifindex[ifindexkey])
                interfaces[key] = {}
                interfaces[key]['interface'] = interface
                interfaces[key]['switch'] = keytargets[2]
                interfaces[key]['description'] = description
                interfaces[key]['status'] = status
                interfaces[key]['vlan'] = vlan
                interfaces[key]['duplex'] = duplex
                interfaces[key]['speed'] = speed
                interfaces[key]['type'] = type
                
                if outlets.has_key(key):
                    interfaces[key]['outlet'] = outlets[key]['outlet']
                    interfaces[key]['ruimte'] = outlets[key]['ruimte']
                    interfaces[key]['toepassing'] = outlets[key]['toepassing']

        #print '-----show interface status--------'
        #print interfaces
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(interfaces)
        #sys.exit()

        # Send the router a command
        ###############################
        #show mac address-table
        
        #Cat3750
        #          Mac Address Table
        #-------------------------------------------
        #
        #Vlan    Mac Address       Type        Ports
        #----    -----------       --------    -----
        # All    ffff.ffff.ffff    STATIC      CPU
        # 121    8887.1780.a28a    STATIC      Fa3/0/20
        #1500    000a.8302.0038    STATIC      Fa2/0/12
        
        #Cat4500
        # vlan     mac address     type        protocols               port
        #---------+---------------+--------+---------------------+-------------------------
        # 121      8887.1780.a28a    static ip,ipx,assigned,other GigabitEthernet2/7     
        #1101      7446.a0a0.4b26    static ip,ipx,assigned,other GigabitEthernet2/2
        
        #Cat3850
        # Vlan    Mac Address       Type        Ports
        # ----    -----------       --------    -----
        #  All    0100.0ccc.cccc    STATIC      CPU
        # 3255    ccd8.c130.2cd4    STATIC      Vl3255
        # 1133    0023.2400.6d74    STATIC      Gi1/0/2
        # 1133    3cd9.2b4d.3af5    STATIC      Gi1/0/1
        # 1233    001a.e86f.1c53    STATIC      Gi2/0/48

        remote_conn.send("show mac address-table\n")

        buff = ''
        while not buff.endswith('>') and not buff.endswith('#'):
            if debug:
                print "show mac address-table: while loop fetching until > or #"
            time.sleep(1)
            output = remote_conn.recv(16384)
            if debug:
                print ansi_escape.sub('', output)
            buff += output
            buff = ansi_escape.sub('', buff)

        lines = buff.splitlines()
        for line in lines:
            #print line
            
            #Cat3750
            searchObj = re.search( r'\s{0,3}([0-9]{1,4})\s{4}([a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4})\s{4}(static|dynamic)\s{6}(\S{3,8})', line, re.M|re.I)
            #Cat3850 of 4500
            searchObj = re.search( r'\s*([0-9]{1,4})\s+([a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4})\s+(static|dynamic)\s+(Gi|ip,ipx,assigned,other GigabitEthernet)(\S+)', line, re.M|re.I)
            if searchObj:
                vlan = searchObj.group(1)
                mac = searchObj.group(2)
                mactype = searchObj.group(3).lower()
                interface = 'Gi' + searchObj.group(5)
                #print 'vlan:%s  mac:%s  type:%s  interface:%s'  %  (vlan, mac, type, interface)
                
                if interface in targets[keytargets]['uplink']:
                    #print 'Gevonden uplink interface:%s overslaan MAC entry' % interface
                    continue
                
                ifindexkey = (targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], interface)
                #key = (building, device, interface)
                key = (keytargets[1], targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], ifindex[ifindexkey])
                #interfaces[key] = {}
                if interfaces[key].has_key('mac'):
                    #print 'heeft mac toevoegen'
                    interfaces[key]['mac'].append(mac + ' (' + vlan + ')')
                else:
                    #print 'heeft geen mac maken en toevoegen'
                    interfaces[key]['mac'] = []
                    interfaces[key]['mac'].append(mac + ' (' + vlan + ')')
                
                #Add IP entry if found in ARP table
                if mac2ip.has_key(mac):
                    if not interfaces[key].has_key('ip'):
                        interfaces[key]['ip'] = []
                    interfaces[key]['ip'].append(mac2ip[mac]['ip'])
                    if mac2ip[mac].has_key('hostname'):
                        if not interfaces[key].has_key('hostname'):
                            interfaces[key]['hostname'] = []
                        interfaces[key]['hostname'].append(mac2ip[mac]['hostname'])
                    mac2ip[mac]['gebouw'] = keytargets[1]
                    mac2ip[mac]['device'] = targets[keytargets]['ser'] + '-' + targets[keytargets]['kast']
                    mac2ip[mac]['interface'] = interface

        #print '-----show mac address-table static--------'
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(interfaces)
        
        #show authentication sessions
        #Cat3750
        #Interface  MAC Address     Method   Domain   Status         Session ID
        #Fa3/0/17   (unknown)       mab      UNKNOWN  Running        0A14FF0A0000091F4D272780
        #Fa3/0/13   (unknown)       mab      UNKNOWN  Running        0A14FF0A0000092F4D7F3E2D
        #Fa3/0/19   (unknown)       mab      UNKNOWN  Running        0A14FF0A000009444DA5C6FB
        #Fa3/0/16   (unknown)       mab      UNKNOWN  Running        0A14FF0A0000095D4E68BC83
        #Fa3/0/8    0001.3e34.5a5c  mab      DATA     Authz Success  0A14FF0A0000093F4D807296
        #Fa2/0/48   001a.e86f.155d  mab      VOICE    Authz Success  0A14FF0A0000068B1A886C4C
        #Fa3/0/15   9890.96bc.abfa  mab      DATA     Authz Success  0A14FF0A000008C4473ACC78
        #Fa2/0/30   001c.ab45.2ff6  mab      DATA     Authz Failed   0A14FF0A000008C04730CA36
        
        #Cat4500
        #Interface    MAC Address    Method  Domain  Status Fg Session ID
        #Gi2/45       000c.ab28.4ae7 mab     DATA    Auth      0A14FF010000079B37BA9C98
        #Gi2/7        8887.1780.a28a mab     DATA    Auth      0A14FF010000083A38D68874
        #Gi2/18       001f.5517.55cd mab     DATA    Auth      0A14FF01000007C537C83904
        #Gi3/39       000f.1100.39e6 mab     DATA    Unauth    0A14FF4700002E3D6F085E84

        remote_conn.send("show authentication sessions\n")

        buff = ''
        while not buff.endswith('>') and not buff.endswith('#'):
            if debug:
                print "show authentication sessions: while loop fetching until > or #"
            time.sleep(1)
            output = remote_conn.recv(16384)
            if debug:
                print ansi_escape.sub('', output)
            buff += output
            buff = ansi_escape.sub('', buff)

        lines = buff.splitlines()
        for line in lines:
            print line
            #TODO Status kolom NIET GOED waarde Auth Unauth
            searchObj = re.search( r'(\S+)\s+(\(unknown\)|[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4})\s+(\S+)\s+(\S+)\s+(\S+)', line, re.M|re.I)
            if searchObj:
                interface = searchObj.group(1)
                isemac = searchObj.group(2)
                method = searchObj.group(3)
                domain = searchObj.group(4)
                status = searchObj.group(5)

                ifindexkey = (targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], interface)
                #key = (building, device, interface)
                key = (keytargets[1], targets[keytargets]['ser'] + '-' + targets[keytargets]['kast'], ifindex[ifindexkey])
                if interfaces[key].has_key('isemac'):
                    interfaces[key]['isemac'].append(isemac + ' (' + domain + ')')
                else:
                    interfaces[key]['isemac'] = []
                    interfaces[key]['isemac'].append(isemac + ' (' + domain + ')')
        
        #print '-----show authentication sessions--------'
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(interfaces)
        
        exit_switch(remote_conn)
        remote_conn_pre.close()
    
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(targets)
    
    
    #Done collecting info start generating output
    generate_html(plaatsen, gebouwen, targets, interfaces, ip2mac)
    
    log.info('DONE')

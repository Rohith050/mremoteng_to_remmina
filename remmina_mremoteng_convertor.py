import base64
from Crypto.Cipher import DES3, AES
import hashlib
from pathlib import Path, PurePath
import argparse
from lxml import etree
import xml.etree.ElementTree as ET
import copy

rdp_skeleton = {
    'password': '',
    'gateway_username': '',
    'notes_text': '',
    'window_height': 510,
    'vc': '',
    'scale': 2,
    'ssh_tunnel_loopback': 0,
    'serialname': '',
    'preferipv6': 0,
    'printer_overrides': '',
    'name': '',
    'console': 0,
    'colordepth': 64,
    'security': '',
    'precommand': '',
    'disable_fastpath': 0,
    'postcommand': '',
    'multitransport': 0,
    'group': '',
    'server': '',
    'glyph-cache': 0,
    'ssh_tunnel_enabled': 0,
    'disableclipboard': 0,
    'parallelpath': '',
    'cert_ignore': 0,
    'gateway_server': '',
    'serialpermissive': 0,
    'protocol': 'RDP',
    'old-license': 0,
    'ssh_tunnel_password': '',
    'resolution_mode': 0,
    'disableautoreconnect': 0,
    'loadbalanceinfo': '',
    'clientbuild': '',
    'clientname': '',
    'resolution_width': 800,
    'relax-order-checks': 0,
    'username': '',
    'gateway_domain': '',
    'serialdriver': '',
    'domain': '',
    'gateway_password': '',
    'smartcardname': '',
    'serialpath': '',
    'exec': '',
    'enable-autostart': 0,
    'usb': '',
    'shareprinter': 0,
    'viewmode': 1,
    'shareparallel': 0,
    'ssh_tunnel_passphrase': '',
    'quality': 0,
    'disablepasswordstoring': 0,
    'parallelname': '',
    'execpath': '',
    'shareserial': 0,
    'sharefolder': '',
    'sharesmartcard': 0,
    'ssh_tunnel_username': '',
    'resolution_height': 600,
    'timeout': '',
    'useproxyenv': 0,
    'dvc': '',
    'microphone': '',
    'gwtransp': 'http',
    'ssh_tunnel_privatekey': '',
    'ssh_tunnel_auth': 0,
    'ignore-tls-errors': 1,
    'window_maximize': 1,
    'ssh_tunnel_server': '',
    'gateway_usage': 0,
    'window_width': 678,
    'sound': 'off',
}

ssh_skeleton = {
    'window_width': '678',
    'username': '',
    'name': '',
    'password': '',
    'ssh_proxycommand': '',
    'ssh_passphrase': '',
    'ssh_charset': '',
    'precommand': '',
    'ssh_privatekey': '',
    'sshlogenabled': '0',
    'ssh_tunnel_enabled': '0',
    'ssh_auth': '0',
    'ignore-tls-errors': '1',
    'postcommand': '',
    'disablepasswordstoring': '0',
    'server': '',
    'ssh_color_scheme': 0,
    'audiblebell': 0,
    'ssh_tunnel_username': '',
    'ssh_hostkeytypes': '',
    'window_maximize': 1,
    'ssh_tunnel_password': '',
    'enable-autostart': 0,
    'sshlogfolder': r'',
    'ssh_tunnel_server': '',
    'group': '',
    'ssh_ciphers': '',
    'ssh_tunnel_auth': 0,
    'ssh_kex_algorithms': '',
    'ssh_compression': 1,
    'notes_text': '',
    'ssh_tunnel_loopback': 0,
    'window_height': 510,
    'exec': '',
    'viewmode': 1,
    'sshlogname': r'',
    'ssh_tunnel_passphrase': '',
    'ssh_tunnel_privatekey': '',
    'ssh_stricthostkeycheck': '0',
    'protocol': 'SSH'
}

vnc_skeleton = {
    'keymap': '',
    'showcursor': 0,
    'colordepth': 32,
    'quality': 9,
    'ssh_tunnel_password': '',
    'postcommand': '',
    'server': '',
    'username': '',
    'name': '',
    'ssh_tunnel_enabled': 0,
    'enable-autostart': 0,
    'password': '',
    'precommand': '',
    'disableencryption': 0,
    'group': '',
    'disablepasswordstoring': 0,
    'protocol': 'VNC',
    'disableclipboard': 0,
    'viewonly': 0,
    'ssh_tunnel_server': '',
    'ssh_tunnel_loopback': 0,
    'ssh_tunnel_auth': 0,
    'ignore-tls-errors': 1,
    'ssh_tunnel_username': '',
    'ssh_tunnel_passphrase': '',
    'ssh_tunnel_privatekey': '',
    'notes_text': '',
    'proxy': '',
    'disableserverinput': 0

}


def encrypt_remmina_password(password):
    secret = base64.b64decode(remmina_key)
    pad = 8 - len(password) % 8
    password = password + pad * chr(0)
    x = DES3.new(secret[:24], DES3.MODE_CBC, secret[24:]).encrypt(password.encode())
    return base64.b64encode(x).decode()


def decrypt_mremoteng_password(encryptedpassword):
    if not encryptedpassword:
        return ''
    encrypted_data = encryptedpassword
    encrypted_data = base64.b64decode(encrypted_data)
    salt = encrypted_data[:16]
    associated_data = encrypted_data[:16]
    nonce = encrypted_data[16:32]
    ciphertext = encrypted_data[32:-16]
    tag = encrypted_data[-16:]
    key = hashlib.pbkdf2_hmac("sha1", mremoteng_key.encode(), salt, 1000, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


def handle_ssh(element, groupname):
    local_skeleton = copy.deepcopy(ssh_skeleton)
    local_skeleton['name'] = element.attrib['Name']
    local_skeleton['username'] = element.attrib['Username']
    local_skeleton['password'] = encrypt_remmina_password(decrypt_mremoteng_password(element.attrib['Password']))
    local_skeleton['server'] = '{}:{}'.format(element.attrib['Hostname'], element.attrib['Port'])
    local_skeleton['group'] = groupname
    create_remmina_file(local_skeleton)


def handle_rdp(element, groupname):
    local_skeleton = copy.deepcopy(rdp_skeleton)
    local_skeleton['name'] = element.attrib['Name']
    local_skeleton['username'] = element.attrib['Username']
    local_skeleton['password'] = encrypt_remmina_password(decrypt_mremoteng_password(element.attrib['Password']))
    local_skeleton['domain'] = element.attrib['Domain']
    local_skeleton['server'] = '{}:{}'.format(element.attrib['Hostname'], element.attrib['Port'])
    local_skeleton['group'] = groupname
    create_remmina_file(local_skeleton)


def handle_telent(element, groupname):
    local_skeleton = copy.deepcopy(ssh_skeleton)
    local_skeleton['name'] = element.attrib['Name']
    local_skeleton['username'] = element.attrib['Username']
    local_skeleton['server'] = '{}:22'.format(element.attrib['Hostname'])
    local_skeleton['password'] = encrypt_remmina_password(decrypt_mremoteng_password(element.attrib['Password']))
    local_skeleton['group'] = groupname
    create_remmina_file(local_skeleton)


def handle_vnc(element, groupname):
    local_skeleton = copy.deepcopy(vnc_skeleton)
    local_skeleton['name'] = element.attrib['Name']
    local_skeleton['username'] = element.attrib['Username']
    local_skeleton['password'] = encrypt_remmina_password(decrypt_mremoteng_password(element.attrib['Password']))
    local_skeleton['server'] = '{}:{}'.format(element.attrib['Hostname'], element.attrib['Port'])
    local_skeleton['group'] = groupname
    create_remmina_file(local_skeleton)


def create_remmina_file(skeleton):
    t_group = skeleton['group'] if skeleton['group'] else 'group'
    file_name = '{}_{}_{}_{}.remmina'.format(t_group.lower().replace('/', '-'), skeleton['protocol'].lower(),
                                             skeleton['name'].lower(),
                                             skeleton['server'].replace('.', '-').replace(':', '-'))
    with open(str(PurePath(remmina_folder).joinpath(file_name)), 'w') as f:
        f.write('[remmina]\n')
        for key, value in skeleton.items():
            f.write('{}={}\n'.format(key, str(value)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Remmina_Convertor')
    requiredNamed = parser.add_argument_group('required arguments')

    requiredNamed.add_argument('-f', '--mremoteng_xml_path',
                               help='Mremoteng xml config file', required=True)
    requiredNamed.add_argument('-rk', '--remmina_key',
                               help='Remmina key used to encrypt passwords. '
                                    'Generally found in ~/.config/remmina/remmina.pref', required=True)
    requiredNamed.add_argument('-mk', '--mremoteng_key',
                               help='mremoteng secret key', default="mR3m", required=False)
    requiredNamed.add_argument('-ts', '--convert_telnet_to_ssh',
                               help='Converts telnet to ssh sessions. Else telnet sessions will be skipped',
                               choices=[True, 'true', False, 'false'],
                               type=lambda s: s.lower() in ['true', 't', 'yes', '1'],
                               default=True, required=False)

    args = parser.parse_args()
    root_path = Path(args.mremoteng_xml_path)

    global remmina_folder
    remmina_folder = Path('remmina_converted')
    remmina_folder.mkdir(exist_ok=True)

    global remmina_key, mremoteng_key
    remmina_key = args.remmina_key
    mremoteng_key = args.mremoteng_key

    tree = ET.parse(args.mremoteng_xml_path)
    root = tree.getroot()

    def handle_node(element, group_name=''):
        for child in element:
            if child.attrib['Type'] == 'Connection':
                group_name = group_name
                if child.attrib['Protocol'] == "SSH2":
                    handle_ssh(child, group_name)
                elif child.attrib['Protocol'] == 'RDP':
                    handle_rdp(child, group_name)
                elif child.attrib['Protocol'] == 'Telnet':
                    if args.convert_telnet_to_ssh:
                        handle_telent(child, group_name)
                    else:
                        print("Skipping telnet session: {}".format(child.attrib['Name']))
                elif child.attrib['Protocol'] == 'VNC':
                    handle_vnc(child, group_name)
                else:
                    print("Unknown protocol: {}".format(child.attrib['Protocol']))
            elif child.attrib['Type'] == 'Container':
                handle_node(child, group_name + '/' + child.attrib['Name'] if group_name else child.attrib['Name'])

    handle_node(root)

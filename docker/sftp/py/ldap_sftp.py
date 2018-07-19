#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
##############################################################################
# dependency:
# modules:
# python 3.2+
# ldap
# unix packages:
# sudo
#
# Script name: ldap_tools.py
#
# Author: MiZo <mihails.zotovs@accenture.com>
#
# Polls and filters from Active Directory: sftp OUs and users.
# one click, full blown sftp rollout
#
##############################################################################

import sys
import json
from subprocess import Popen, PIPE, STDOUT
from ldap3 import Server, Connection, ALL, NTLM

AD_HOST = "192.168.1.105"
SFTP_BASEDN = "ou=sftp_root,dc=mizo,dc=local"
AD_OU_FILTER = "(objectClass=*)"
AD_BIND_USER = "mizo\\administrator"
AD_BIND_PWD = "Ghbdtnrfrltkf&7"
ATTRS = ["*"]
ADDPOLLTXT = sys.path[0] + "/adpoll.txt"

SFTP_HOST_URL = "localhost"
SFTP_ROOT = "/sftp_root"
SFTP_ROOT_USER = "sftp_root"
SFTP_SSH_USER = "root"
SFTP_SSH_KEY = "/home/lamersons/.ssh/uponor_sftp.pem"

def exec_r_cmd(cmd_list):
    i = ""
    for cmd in cmd_list:
        try:
            print(str(cmd))
            c = ['ssh', '-i', SFTP_SSH_KEY, SFTP_SSH_USER + "@" + SFTP_HOST_URL, cmd]
            x = Popen(c, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            i = x.stdout.read().decode("UTF-8")
            print(x.stdout.read().decode("UTF-8") or x.stderr.read().decode("UTF-8"))
        except Exception as e: print(e)
    return i

def get_conn(u=AD_BIND_USER, p=AD_BIND_PWD, h=AD_HOST):
    s = Server(AD_HOST)
    c = Connection(s, AD_BIND_USER, AD_BIND_PWD, auto_bind=True)
    return c

def poll_sftp_dn(c, filter="user"):
    c.search(SFTP_BASEDN, "(objectClass=%s)" % filter, attributes=ATTRS)
    return [e.entry_dn.split(",DC=mizo,DC=local")[0] for e in c.entries]

def create_folders(sftp_dn):
    print("\n\n>>> creating folder structure <<<")
    li = ["/"+"/".join(d) for d in [dn.replace("OU=","").split(",")[::-1] for dn in sftp_dn]]
    for l in li: exec_r_cmd(["mkdir -p %s" % l])
    return li

def prune_folders(f_li):
    print("\n\n>>> pruning unix folders which are not in AD <<<")
    unix_f_li = exec_r_cmd(["ls -R " + SFTP_ROOT]).split("\n")
    unix_f_li = [x.replace(":","") for x in list(unix_f_li) if ":" in x]
    del_f_li = [x for x in unix_f_li if x not in f_li]
    for f in del_f_li: exec_r_cmd(["rm -rf " + f])
    # print(del_f_li)

def create_users(sftp_dn):
    li = [u.split(",")[0].replace("CN=","") for u in sftp_dn]
    for u in li:
        print("\n\n>>> creating sftp user for user: {0} <<<".format(u))
        exec_r_cmd(["echo -e 'y' | useradd -s '/sbin/nologin' -d /home/{0} {0}".format(u)])
        gen_key_pair(u)
        add_pub_key(u)
    return li

def prune_users(u_li):
    print("\n\n>>> pruning unix users which are not in AD <<<")
    unix_u_li = exec_r_cmd(["groups " + SFTP_ROOT_USER]).replace("\n","").split(" : ")[1].split(" ")
    del_u_li = [x for x in unix_u_li if not x in u_li]
    for u in del_u_li: exec_r_cmd(["userdel -rf {0}; groupdel {0}".format(u)])

def set_folder_chmod():
    print("\n\n>>> setting folder permissons <<<")
    exec_r_cmd(['chmod -R g+s %s'%(SFTP_ROOT), 'chmod -R 771 %s'%(SFTP_ROOT), 'chmod 755 %s'%(SFTP_ROOT)])

def set_folder_chown(sftp_dn):
    print("\n\n>>> setting folder groups <<<")
    c_li = ['chown -R {0}:{0} {1}'.format(SFTP_ROOT_USER, SFTP_ROOT)]
    u_li = [u.replace("OU=","").replace("CN=","") for u in sftp_dn]
    for u in u_li:
        u_spl = u.split(",")
        if len(u_spl) > 2:
            c_li.append('chown -R {0}:{0} {1}'.format(u_spl[0], "/" + "/".join(u_spl[1:][::-1])))
    exec_r_cmd(c_li)

def set_unix_groups(sftp_dn):
    print("\n\n>>> setting unix groups <<<")
    c_li = []
    u_dn_li = [u.replace("CN=","").replace("OU=","") for u in sftp_dn]
    u_li = [u.split(",")[0].replace("CN=","") for u in sftp_dn]
    for dn in u_dn_li:
        dn_spl = dn.split(",")
        for u in u_li:
            if u in dn_spl[1:] and dn_spl[0] != u: c_li.append("usermod -a -G %s %s" % (dn_spl[0], u))
    exec_r_cmd(c_li)

def add_pub_key(user):
    print(">>> adding rsa key pair to authorized for user: {0} <<<".format(user))
    exec_r_cmd(["sudo -H -u {0} bash -c \"cat /home/{0}/.ssh/{0}.pub > /home/{0}/.ssh/authorized_keys\"".format(user)])

def gen_key_pair(user):
    print(">>> generating rsa key pair for user: {0} <<<".format(user))
    exec_r_cmd(["sudo -H -u {0} bash -c \"echo -e  \'n'| ssh-keygen -b 2048 -t rsa -f /home/{0}/.ssh/{0} -q -N \'\' \"".format(user)])

def install_sudo():
    print("\n\n>>> checkng for sudo package <<<")
    if "not installed" in exec_r_cmd(["rpm -q sudo"]): exec_r_cmd(["yum makecache", "yum install sudo -y"])

def start_container():
    print("\n\n>>> Starting sftp container <<<")
    if "sftp_server" and "Up" not in exec_r_cmd(["docker-compose -f docker-compose.yml ps"]):
        exec_r_cmd(["docker-compose -f ../docker/docker-compose.yml build",
                    "docker-compose -f ../docker/docker-compose.yml up -d"])
    else: print("container is running")

# def save_adpoll(user, organizationalUnit):
#     with open(ADDPOLLTXT, "w") as f:
#         f.write(",".join(user) + ",".join(organizationalUnit))

if __name__ =="__main__":
    u_dn_li = poll_sftp_dn(get_conn(), "user")
    ou_dn_li = poll_sftp_dn(get_conn(), "organizationalUnit")
    if all([u_dn_li, ou_dn_li]): print("\n\n>>> sucessfuly polled active directory <<<")
    else: sys.exit("failed to poll active directory")

    # install_sudo()
    # f_li = create_folders(ou_dn_li)
    # u_li = create_users(u_dn_li)
    # set_folder_chmod()
    # set_folder_chown(u_dn_li)
    # set_unix_groups(u_dn_li)
    # prune_users(u_li)
    # prune_folders(f_li)
    start_container()
    # # save_adpoll(u_li, f_li)

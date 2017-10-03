#!/usr/bin/env python

###################################################################################
# Empire client script                                                            #
# Author: @xorrior                                                                #
# Purpose: This script will allow you to connect to an Empire multi-user instance #
# License: BSD3-Clause                                                            #
###################################################################################


import sys
import rpyc
import json
import requests
import argparse
import cmd
import shlex

introArt = """
           /\:::::/\            /\:::::/\
          /::\:::/::\          /==\:::/::\
         /::::\_/::::\   .--. /====\_/::::\
        /_____/ \_____\-' .-.`-----' \_____\
        \:::::\_/:::::/-. `-'.-----._/:::::/
         \::::/:\::::/   `--' \::::/:\::::/
          \::/:::\::/          \::/:::\::/
           \/_____\/            \/_____\/

           EMPIRE CLIENT BETA-1.0
"""

class ClientMenu(cmd.Cmd):
    
    def __init__(self, args=None):
        cmd.Cmd.__init__(self)

        if len(args) > 0 and args.hostname and args.port and args.restuser and args.restpassword:
            self.hostname = args.hostname 
            self.restport = args.port
            self.restuser = args.restuser
            self.restpassword = args.restpassword

            self.loginuri = "https://"+self.hostname+":"+self.restport+"/api/admin/login"
            headers = {'Content-Type':'application/json'}
            data = json.dumps({"username":self.restuser,"password":self.restpassword})

            # attempt to auth with the rest api
            try:
                r = requests.post(self.loginuri, data=data, headers=headers)
            except:
                print "[-] Unable to connect/authenticate with the rest endpoint"
                sys.exit(-1)

            if r.status_code != 200:
                print "[-] Unable to connect the rest api. Response from server:\n" + str(r.status_code)
                sys.exit(-1)

            self.restToken = json.loads(r.text)['token']
        else:
            print "[-] Not enough arguments given"
            sys.exit(-1)

        self.session = None
        self.agentLocalCache = []
        self.intro = introArt
        self.prompt = "console > "

    def agentConnect(self, sessionID, username, port, keyfile, certfile):
        """
        Function to connect to the remote empire instance to interact with an agent
        """
        self.session = rpyc.ssl_connect(self.hostname, port, keyfile=keyfile, certfile=certfile, config={"allow_all_attrs":True})


    def showActiveAgents(self):
        '''Displays all of the active agents in the console'''
        
        agents = self.getLiveAgents()
        if agents != "":
            
            print "[Name]\t[Lang]\t[Hostname]\t[Username]\t[ProcName]\t[ProcID]\t[LastSeen]"
            for agent in agents:
                if agent['language'] == 'powershell':
                    lang = 'ps'
                else:
                    lang = 'py'

                if agent['name'] not in self.agentLocalCache:
                    self.agentLocalCache.append(agent['name'])

                print "%s\t%s\t%s\t%s\t%s\t%s\t%s" % (agent['name'], lang, agent['hostname'], agent['username'], agent['process_name'], agent['process_id'], agent['lastseen_time'])
    
    def getLiveAgents(self):
        '''Responsible for obtaining a list of all the active agents'''
        uri = "https://%s:%s/api/agents" % (self.hostname, self.restport)
        params = {"token":self.restToken}

        try:
            r = requests.get(uri, params=params, verify=False)
        except:
            print "[-] The request to the server failed"
            return ""

        if r.status_code != 200:
            print "[-] The server responded with the status code: %s" % (str(r.status_code))
            return ""
        else:
            return json.loads(r.text)['agents']

    def getLiveListeners(self):
        '''Responsible for obtaining a list of all the active listeners'''
            
    def showActivelisteners(self):
        '''Fetches all of the active listeners'''

    def do_interact(self, line):
        '''Interact with an active agent'''

        sessionID = line.strip()

        if sessionID not in self.getLiveAgents():
            print "[-] Agent does not exist"
            return ""

        if not self.session:
            print "[-] You are not currently connected to the server"
            usrname = raw_input(prompt="Please enter the desired username: ")
            keyfile = raw_input(prompt="Please enter the path to the client SSL key file: ")
            certfile = raw_input(prompt="Please enter the path to the client SSL certificate file")
            port = raw_input(prompt="Please enter the port for the multi-session server")

            try:
                self.session = rpyc.ssl_connect(self.hostname, port, keyfile=keyfile, certfile=certfile, config={"allow_all_attrs":True})
            except:
                return ""

        self.session.root.handler(sessionID, usrname, sys.stdin, sys.stdout)
            

    def do_agents(self, line):
        '''Show all active agents'''
        self.showActiveAgents()

    def do_listeners(self, line):
        '''Show all active listeners'''
        self.showActivelisteners()
    
    def do_exit(self, line):
        '''Exit the client'''

    def complete_interact(self, text, line, begidx, endidx):
        '''Tab-complete an interact command'''

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in self.agentLocalCache if s.startswith(mline)] 





if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    mainGroup = parser.add_argument_group('Empire Client Options')
    mainGroup.add_argument('-h','--hostname',nargs=1,help='Hostname or IP address of the Empire server')
    mainGroup.add_argument('--restport',nargs=1, help='Port that is configured for the rest API on the Empire server.')
    mainGroup.add_argument('--restUser',nargs=1, help='The rest user to connect to the API.')
    mainGroup.add_argument('--restPass',nargs=1, help='Password for the rest user.')
    mainGroup.add_argument('--keyfile', nargs=1, help='Private key for SSL')
    mainGroup.add_argument('--certfile', nargs=1, help='Certificate for SSL')

    args = parser.parse_args()

    menu = ClientMenu(args=args)

    menu.cmdloop()

# coding: utf-8

import os
import json
import getopt
import requests
import dns.resolver
import tldextract
import imaplib, smtplib, poplib
import gevent
from gevent import monkey; monkey.patch_all()
from lxml import objectify, etree

import sys
reload(sys) 
sys.setdefaultencoding('utf8')


def patch_send():
    import httplib
    old_send = httplib.HTTPConnection.send
    def new_send(self, data):
        print data
        return old_send(self, data)
    httplib.HTTPConnection.send = new_send
    
class FetchException(Exception):
    pass

class MailConfig(object):    
    nameservers = ['8.8.8.8', '8.8.4.4', '208.67.222.222', '114.114.114.114',
                   '119.29.29.29']        
    hostprefix  = ['mail', 'www', 'webmail', 'email', 'owa', 'exchange',
                   'mailhost', 'mailin','mail1', 'mail2', 'mail3', 'mx', 
                   'mx1', 'mbox', 'mobile', 'web', 'securemail', 'secure',
                   'relay', '']   

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.nameservers

    def getmx(self, domain):
        result = []
        with gevent.Timeout(16.0, False) as _timeout:
            try:
                myAnswer = self.resolver.query(domain, 'MX')
                for i in myAnswer:
                    result.append(str(i.exchange))
            except: 
                pass
        return result
    
    def request(self, url, params=None, timeout=16.0):
        return requests.get(url, params=params, timeout=timeout)
      
    def _substitute_username(self, username, email):
        local_part, domain = email.split('@', 2)
        username = username.replace('%EMAILADDRESS%', email)
        username = username.replace('%EMAILLOCALPART%', local_part)
        username = username.replace('%EMAILDOMAIN%', domain)
        return username

    def _extract_protocol_config(self, kind, protocol, xml, email):
        tree = xml.find('.//%sServer[@type="%s"]' % (kind, protocol))
        if tree is None:
            return None
        username = self._substitute_username(str(tree.username), email)
        authentication = str(tree.authentication).lower()
        socket_type = str(tree.socketType).lower()
        config = dict(protocol=protocol,
                      hostname=str(tree.hostname),
                      port=int(tree.port),
                      socket_type=socket_type,
                      authentication=authentication,
                      username=username)
        if kind == 'outgoing':
            try:
                restriction = str(tree.restriction).lower()
            except AttributeError:
                restriction = None
            config['restriction'] = restriction
        return config

    def parser(self, packet, email):
        result = {}
        xml = objectify.fromstring(packet)
        smtp_config = self._extract_protocol_config('outgoing', 'smtp', xml, email)
        pop3_config = self._extract_protocol_config('incoming', 'pop3', xml, email)
        imap_config = self._extract_protocol_config('incoming', 'imap', xml, email)
        for config in [smtp_config, pop3_config, imap_config]:
            if config:
                result.setdefault(config['protocol'], config)
        if not result:
            raise FetchException('Find Failed.')
        return result

    def fetch_config_from_isp(self, email):
        domain = email.split('@', 2)[-1]
        resp = self.request('http://autoconfig.%s/mail/config-v1.1.xml' % domain,
                            params={'emailaddress': email})
        return self.parser(resp.content, email)  

    def fetch_config_from_db(self, email):
        domain = email.split('@', 2)[-1]
        resp = self.request(
            'https://autoconfig.thunderbird.net/v1.1/%s' % domain)
        return self.parser(resp.content, email)

    def fetch_config_from_mx(self, email):
        domain = email.split('@', 2)[-1]
        mx = self.getmx(domain)
        if not mx:
            return None
        ext = tldextract.extract(mx[0])
        domain = ext.registered_domain
        resp = self.request(
            'https://autoconfig.thunderbird.net/v1.1/%s' % domain)
        return self.parser(resp.content, email)

    def detect(self, protocol, host, port, use_ssl=0):
        try:    
            server = None    
            with gevent.Timeout(3.0) as _timeout:                 
                if protocol == 'imap':                        
                    server = imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)           
                if protocol == 'pop3':
                    server = poplib.POP3_SSL(host, port) if use_ssl else poplib.POP3(host, port)
                if protocol == 'smtp':                                
                        server = smtplib.SMTP_SSL(host, port) if use_ssl else smtplib.SMTP(host, port)            
                if server:
                    if protocol == 'imap':
                        server.logout()
                    else:
                        server.quit()
        except:
            return False
        return True     

    def fetch_config_from_guess(self, email):
        result = {}
        domain = email.split('@', 2)[-1]
        standport = {           
            'imap': {'ports': [993,     143], 'prefix': ['imap'] + hostprefix},
            'pop3': {'ports': [995,     110], 'prefix': ['pop', 'pop3'] + hostprefix}, 
            'smtp': {'ports': [465, 25, 578], 'prefix': ['smtp'] + hostprefix},
        }
        for protocol, value in standport.items():            
            fquit = None                
            fport = value['ports'][0]
            for port in value['ports']:
                if fquit is not None: 
                    break         
                use_ssl = True if fport==port else None
                socket_type = 'ssl' if use_ssl else 'plain/starttls'                                                         
                for prefix in value['prefix']:
                    hostname = '%s.%s' % (prefix, domain)
                    hostname = hostname.lstrip('.')                 
                    if self.detect(protocol, hostname, port, use_ssl):
                        fquit  = True
                        config = dict(protocol=protocol,  
                                      hostname=hostname,
                                      port=int(port),
                                      socket_type=socket_type,
                                      authentication=None,
                                      username=email)
                        result[protocol] = config         
                        break
        if not result:
            raise FetchException('Find Failed.')      
        return result        

    def find_config(self, email):              
        for func in (self.fetch_config_from_isp,                    
                     self.fetch_config_from_db,
                     self.fetch_config_from_mx,
                     self.fetch_config_from_guess):
            try:
                return func(email)
            except :
                pass
        return None

class Scanner(object):  
    
    def __init__(self, task_file, threads=100):
        self.task_file = task_file
        self.threads = threads
        self.config = MailConfig()
              
    def worker(self, *args, **kwargs):
        worker_id = args[0]
        while True:
            line = self.fd_task_file.readline()
            if not line: 
                break            
            domain = line.strip()
            email = 'email@%s' % domain.split('@')[-1]
            servers = self.config.find_config(email)                        
            if servers:
                print >> self.fd_ok_file, json.dumps({'domain':domain, 'servers':servers})
                self.fd_ok_file.flush()
            else:
                print >> self.fd_bad_file, domain
                self.fd_bad_file.flush()
     
    
    def start(self):
        if not self.task_file or not os.path.exists(self.task_file):
            print "Error: invalid file path [%s]" % self.task_file
            sys.exit(-1)                         
        basename = os.path.basename(self.task_file).split('.')[0]              
        self.fd_task_file = open(self.task_file, 'r')
        self.fd_ok_file = open('%s_ok.txt' % basename, 'w')
        self.fd_bad_file = open('%s_bad.txt' % basename, 'w')          
        try:
            spawn_list = [gevent.spawn(self.worker, i) for i in xrange(self.threads)]
            gevent.joinall(spawn_list) 
        finally:
            self.fd_task_file.close()
            self.fd_ok_file.close()
            self.fd_bad_file.close()
            
def usage():
    print "Usage: mailSettings.py -t taskfile.txt -n 30"
    sys.exit(-1)
    
def main():    
    if len(sys.argv[1:]) < 1:
        usage()
    try: 
        opts, args = getopt.getopt(sys.argv[1:], 'ht:n:', ["help", "taskfile", "threads"])        
    except getopt.GetoptError, e:
        print str(e)
        usage()       

    task_file = None
    thread_num = 30
    
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()                
        elif o in ("-t", "--taskfile"):
            task_file = a                         
        elif o in ("-n", "--threads"):
            thread_num = int(a)     
        else:
            assert False, "Unhandled Options"
    if not task_file: usage()    
                 
    scanner = Scanner(task_file,  thread_num)
    scanner.start()           
       
if __name__ == '__main__': 
    #patch_send()    
    main()




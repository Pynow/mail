#coding: utf-8
import imaplib

try:
    import ssl
    HAVE_SSL = True
except ImportError:
    HAVE_SSL = False

imaplib.Debug = 1

Commands = {
  'STARTTLS': ('NONAUTH')
}

imaplib.Commands.update(Commands)

class IMAP4_STARTTLS(imaplib.IMAP4, object):
    def __init__(self, host, port):
      super(IMAP4_STARTTLS, self).__init__(host, port)
      self._tls_established = False  
    
    def starttls(self, keyfile = None, certfile = None):
          name = 'STARTTLS'
          if not HAVE_SSL:
              raise self.error('SSL support missing')
          if self._tls_established:
              raise self.abort('TLS session already established')
          if name not in self.capabilities:
              raise self.abort('TLS not supported by server')            
          typ, dat = self._simple_command(name)    
          if typ == 'OK':                 
              self.sock = ssl.wrap_socket(self.sock,                                     
                  keyfile, 
                  certfile, 
                  ssl_version=ssl.PROTOCOL_TLSv1)
              self.file.close()
              self.file = self.sock.makefile('rb')
              self._tls_established = True
              self._get_capabilities()
          else:
              raise self.error("Couldn't establish TLS session")
          return self._untagged_response(typ, dat, name)   
    
    def _get_capabilities(self):
        typ, dat = self.capability()
        if dat == [None]:
            raise self.error('no CAPABILITY response from server')
        dat = str(dat[-1])
        dat = dat.upper()
        self.capabilities = tuple(dat.split())    

if __name__ == '__main__':       
    imap = IMAP4_STARTTLS('imap-mail.outlook.com', 143) 
    imap.starttls()  
    imap.login('username@outlook.com', 'password')
    imap.logout()

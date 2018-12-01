#coding: utf-8
import poplib

try:
    import ssl
    HAVE_SSL = True
except ImportError:
    HAVE_SSL = False
    
class POP3_STLS(poplib.POP3, object):
    def __init__(self, host, port):
        super(POP3_STLS, self).__init__(host, port)
        self._tls_established = False        
    
    def capa(self):
        """ Return the capabilities as a dictionary """
        def _parsecap(line):      
            lst = line.decode('ascii').split()
            return lst[0], lst[1:]                        
        caps = {}
        try:
            resp = self._longcmd('CAPA')            
            rawcaps = resp[1]
            for capline in rawcaps:
                capnm, capargs = _parsecap(capline)
                caps[capnm] = capargs                
        except error_proto as _err:
            raise error_proto('-ERR CAPA not supported by server.')
        return caps
    
    def stls(self, keyfile=None, certfile=None):
        """ Start a TLS session on the active connection """       
        if not HAVE_SSL:
            raise error_proto('-ERR TLS support missing')
        if self._tls_established:
            raise error_proto('-ERR TLS session already established')
        caps = self.capa()    
        if not 'STLS' in caps:
            raise error_proto('-ERR STLS not supported by server')
        resp = self._shortcmd('STLS')        
        if resp.startswith('+OK'):
            self.sock = ssl.wrap_socket(self.sock, keyfile, certfile)
            self.file = self.sock.makefile('rb')
            self._tls_established = True
        else:
            raise self.error("Couldn't establish TLS session")                
        return resp            
    
if __name__ == '__main__':
    conn = None
    try:
        conn = POP3_STLS('pop.163.com', 110)
        try:            
            conn.stls()
        except:
            pass
        print conn.getwelcome()
        conn.user('username@163.com')
        conn.pass_('password')
    finally:
        if conn:
            conn.quit()
        
    

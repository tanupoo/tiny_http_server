import ssl
from socket import socket

class logging_ssl_socket(ssl.SSLSocket):

    def default_logger(self, *args, **kwargs):
        pass

    def __init__(self, *args, **kwargs):
        if "logger" in kwargs:
            self.logger = kwargs.pop("logger")
        else:
            self.logger = self.default_logger
        super().__init__(*args, **kwargs)

    def accept(self):
        '''
        modified ssl.SSLSocket.accept() of ssl.py.
        '''
        #import pdb; pdb.set_trace()
        newsock, addr = socket.accept(self)
        self.logger.debug("Connection from {}".format(addr))
        self.logger.debug("begin SSL handshake")
        newsock = self.context.wrap_socket(newsock,
                    do_handshake_on_connect=self.do_handshake_on_connect,
                    suppress_ragged_eofs=self.suppress_ragged_eofs,
                    server_side=True)
        self.logger.debug("end SSL handshake: ssl_ver={}({})"
                          .format(ssl.get_protocol_name(self.ssl_version),
                                  self.ssl_version))
        '''
        if not server_side:
            print(self.getpeercert())
            print(self.context.get_ca_certs())
        #print(self.context.check_hostname)
        #print(type(self.cipher()))
        #print(type(self.shared_ciphers()))
        #print(type(self.compression()))
        #print(self.context.session_stats())
        '''
        return newsock, addr


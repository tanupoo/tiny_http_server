#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import argparse
import traceback
import json
import re
import os
from stat import S_ISREG
import mimetypes
import logging
import logging.handlers

try:
    from http.server import HTTPServer
    from http.server import BaseHTTPRequestHandler
    from socketserver import ThreadingMixIn
except:
    from BaseHTTPServer import HTTPServer
    from BaseHTTPServer import BaseHTTPRequestHandler
    from SocketServer import ThreadingMixIn

import threading
from logging_ssl_socket import logging_ssl_socket
from ssl import PROTOCOL_TLSv1

#
# XXX don't publish the path in this server, use self.path instead.
#

DEBUG2 = 7
DEBUG3 = 4
DEBUG4 = 1

class TinyHTTPHandler(BaseHTTPRequestHandler):

    __version__ = '0.2'

    protocol_version = 'HTTP/1.1'
    server_version = 'TinyHTTPServer/' + __version__

    re_list_exclude_files = []

    #
    # maximum content size to be handled.
    # a negative value means infinity.
    # it can be changed by defining max_content_size in the config.
    #
    # XXX it should be separated into
    # max_read_content_size and max_write_content_size.
    #
    #max_content_size = 256*1024  # 256KB
    #    if self.server.config.has_key('max_content_size'):
    #        self.max_content_size = self.server.config['max_content_size']
    max_content_size = -1

    def __init__(self, request, client_address, server, **kwargs):
        self.logger = server.config['logger']
        self.re_list_exclude_files = server.config['re_exclude_files']
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def set_server_version(self, name):
        self.server_version = name

    # @return
    #   None: ignore
    #   True: success
    #   False: error
    def file_provider(self):
        ''' file provider.

        @return False something error happened.
        @return True a file was provided.
        '''
        #
        # check whether the path should be excluded.
        #
        for i in self.re_list_exclude_files:
            if i.match(self.path):
                self.logger.debug('exclude by config. [%s]' % self.path)
                return True
        #
        # if the path is "/debug" then ...
        # you can disable it by configuring "/debug" in exclude_files.
        #
        if self.path == '/debug':
            contents = ['%s: %s' % (k,v) for k,v in self.headers.items()]
            self.put_response(contents)
            return True
        # simply checking self.path.
        # should check it more.
        re_2dot = re.compile('\.\.')
        if re_2dot.search(self.path):
            self.logger.error('".." in the path is not allowed.')
            self.send_error_msg(404, 'ERROR: no such file %s' % self.path)
            return False
        # check whether the file exists.
        path = self.server.config['doc_root'] + self.path
        try:
            mode = os.stat(path).st_mode
            if not S_ISREG(mode):
                self.logger.error('not a regular file, %s' % self.path)
                self.send_error_msg(404, 'ERROR: no such file %s' % self.path)
                return False
        except OSError:
            self.logger.error('no such file %s' % self.path)
            self.send_error_msg(404, 'ERROR: no such file %s' % self.path)
            return False
        except Exception as e:
            self.logger.error('internal error, %s' % e)
            return False
        #
        self.send_doc(path)
        return True

    def pre_process(self):
        ''' pre-processing to read the content

        it may be overridden.
        access control should be here.
        '''
        self.logger.debug('thread#=%s' % threading.currentThread().getName())
        self.logger.debug('client=%s' % repr(self.client_address))
        self.logger.debug('request=%s %s %s' %
                (self.command, self.path, self.request_version))
        self.logger.log(DEBUG3, '---BEGIN OF REQUESTED HEADER---')
        self.logger.log(DEBUG3, "\n%s" % '\n'.join(
                ['%s: %s' % (k,v) for k,v in self.headers.items()]))
        self.logger.log(DEBUG3, '---END OF REQUESTED HEADER---')

    def read_content(self):
        ''' read message
        
        may be overridden. '''
        if "Content-Length" in self.headers:
            self.post_read(self.read_length())
        else:
            self.post_read('')

    def read_length(self):
        ''' read message by the content-length. '''
        if "Content-Length" not in self.headers:
            self.send_error_msg(400, 'ERROR: Content-Length must be specified')
            return None
        size = int(self.headers['Content-Length'])
        if self.max_content_size >= 0 and size > self.max_content_size:
            self.send_error_msg(400,
                'ERROR: too large content to be received. > %d' %
                                self.max_content_size)
            return None
        return self.read_once(size)

    def read_once(self, size):
        ''' read message with the specified size and return it. '''
        if size:
            return self.rfile.read(size)
        else:
            return ''

    def post_read(self, contents):
        ''' post process after it read the whole content.

        may be overriddedn.
        it is allowed that contents is a list or a string.
        '''
        self.logger.log(DEBUG3, '---BEGIN OF REQUESTED DATA---')
        self.logger.log(DEBUG3, "\n%s" % contents)
        self.logger.log(DEBUG3, '---END OF REQUESTED DATA---')
        #
        # Here, you can change your own code according to the data posted.
        #
        if self.server.config.get('echo'):
            #
            # just echo the headers and body requested the peer.
            #
            self.put_response(contents)
        else:
            self.put_response('OK')

    def put_response(self, contents, ctype='text/html'):
        ''' make a list of messages.

        may be overriddedn.
        it is allowed that contents is a list or a string.
        '''
        msg_list = []
        msg_list.append(' '.join(
                [self.command, self.path, self.request_version]))
        msg_list.append('\n')
        msg_list.extend(['%s: %s\n' % (k,v) for k,v in self.headers.items()])
        msg_list.append('\n\n')
        if isinstance(contents, list):
            msg_list.extend(contents)
        elif isinstance(contents, bytes):
            msg_list.append(contents.decode(encoding="utf-8"))
        else:
            msg_list.extend(append)
        #
        #self.send_once(''.join(msg_list), ctype=ctype)
        size = 0
        for i in msg_list:
            size += len(i)
        self.send_once(msg_list, size, ctype=ctype)

    def send_once(self, contents, size, ctype=None):
        ''' send a list of messages.
        
        @param contents a list or a stream of messages to be sent.
        @param size the number of size of the messages.
        @param ctype content-type. if None, send_once() tries to guess it.
        '''
        self.send_response(200)
        if ctype:
            self.send_header('Content-Type', ctype)
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', size)
        self.end_headers()
        try:
            for i in contents:
                if isinstance(i, str):
                    self.wfile.write(bytes(i, encoding="utf-8"))
                else:
                    self.wfile.write(i)
        except Exception as e:
            self.send_error_msg(404, 'ERROR: internal error, %s' % e)
            return
        self.logger.log(DEBUG3, '---BEGIN OF RESPONSE---')
        self.logger.log(DEBUG3, 'ctype=%s size=%d' % (ctype, size))
        self.logger.log(DEBUG3, '---END OF RESPONSE---')

    def send_error_msg(self, code, content):
        #self.logger.error(content)
        self.send_error(code, content)
        self.send_header('Connection', 'close')
        self.end_headers()
        if isinstance(content, str):
            self.wfile.write(bytes(content, encoding="utf-8"))
        else:
            self.wfile.write(content)

    def log_error(self, format, *args):
        self.logger.error(format, *args)

    def log_message(self, format, *args):
        self.logger.info(format, *args)

    def send_doc(self, path, ctype=None):
        ''' send a file.

        @param path path to the file name, which is supposed to be existed.
        @param ctype content-type to be sent. if None, the decision is left
               to the python stack.
        '''
        # check the size
        try:
            size = os.stat(path).st_size
            if (self.max_content_size >= 0 and size > self.max_content_size):
                self.send_error_msg(400,
                        'ERROR: too large file size to be sent. > %d' %
                        self.max_content_size)
                return
            f = open(path)
        except Exception as e:
            self.send_error_msg(404, 'ERROR: internal error, %s' % e)
            return
        content = None
        if not ctype:
            ctype = mimetypes.guess_type(path)[0]
            if not ctype:
                ctype = 'text/plain'
        self.send_once(f, size, ctype=ctype)
        f.close()

    def do_GET(self):
        self.pre_process()
        if not self.file_provider():
            self.close_connection = 1

    def do_POST(self):
        self.pre_process()
        try:
            self.read_content()
        except Exception as e:
            self.logger.error(e)
            self.send_error_msg(404, 'ERROR: internal error, %s' % e)

    def do_PUT(self):
        self.pre_process()
        try:
            self.read_content()
        except Exception as e:
            self.logger.error(e)
            self.send_error_msg(404, 'ERROR: internal error, %s' % e)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    def __init__(self, server_address, RequestHandlerClass, config=None):
        self.config = config
        HTTPServer.__init__(self, server_address, RequestHandlerClass)

class TinyHTTPServer():

    config = {}
    configured = False
    logger = None

    '''
    appname: is used in the logger.
    '''
    def __init__(self, handler, appname="TinyHTTPServer"):
        self.handler = handler
        self.appname = appname
        self.__init_logger()

    def __init_logger(self):
        logging.addLevelName(DEBUG2, "DEBUG2")
        logging.addLevelName(DEBUG3, "DEBUG3")
        logging.addLevelName(DEBUG4, "DEBUG4")
        self.logger = logging.getLogger(self.appname)
        self.logger.setLevel(DEBUG4)

    def __set_logger(self, filename, lvl):
        fmt = logging.Formatter(fmt="%(asctime)s:%(name)s:%(levelname)s: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
        if filename in ["stdout", "-"]:
            ch = logging.StreamHandler()
        elif filename == "stderr":
            ch = logging.StreamHandler(stream=sys.stderr)
        else:
            ch = logging.handlers.WatchedFileHandler(filename, "a", "utf-8")
        ch.setFormatter(fmt)
        ch.setLevel(lvl)
        self.logger.addHandler(ch)
        self.config['logger'] = self.logger

    def set_opt(self, name, type=str, default=None, opt=None, required=True):
        '''
        name: attribute name.
        default: applied it if the name is not defined
                 in either config nor arguments.
        opt: overwrite the attribute with it.
        type: int or str
        '''
        if opt is not None:
            self.config[name] = type(opt)
        elif name not in self.config:
            if default == None and required == True:
                raise ValueError("ERROR: %s is required." % name)
            self.config[name] = default
        else:
            # use self.config[name]
            pass
        # then, config[name] will be used as it is.
        self.config[name] = type(self.config[name])

    def set_config(self):
        # do nothing if it is called before.
        if self.configured:
            return
        #
        p = argparse.ArgumentParser()
        p.add_argument('-s', action='store', dest='server_addr',
                       help='specifies the address of the server')
        p.add_argument('-p', action='store', dest='server_port',
                       help='specifies the port number of the server')
        p.add_argument('-c', action='store', dest='config_file',
                       help='specifies the name of the configuration file')
        p.add_argument('-D', action='store', dest='doc_root', default=None,
                    help='specifies the directory name of the document root.')
        p.add_argument('-C', action='store', dest='ch_root', default=0,
                    help='changes the root directory into the document root.')
        p.add_argument('-l', action='store', dest='log_file', default="stdout",
                    help='specifies the log file. stdout, stderr are valid.')
        p.add_argument('-k', action='store', dest='cert_file',
                       default=None, help="""enable secure server and specify a
                       filename including a certificate and private-key.""")
        p.add_argument('--ssl-version', action='store', dest='ssl_ver',
                       default=None, help="specify the SSL version.")
        p.add_argument('-d', action='append_const', dest='_f_debug',
                       default=[], const=1, help="increase debug mode.")
        p.add_argument('--debug', action='store', dest='_debug_level',
                       type=int, default=-1, help="specify a debug level.")
        #
        args = p.parse_args()
        # adjust the debug level.
        #   0: logging.INFO
        #   1: logging.DEBUG
        #   2: DEBUG2
        #   3: DEBUG3
        if len(args._f_debug) and args._debug_level != -1:
            print("ERROR: use either -d or --debug option.")
            exit(1)
        if args._debug_level == -1:
            args._debug_level = 0
        args.debug_level = len(args._f_debug) + args._debug_level
        ## XXX
        #self.config["debug_level"] = 4
        #
        if (args.config_file):
            try:
                self.config = json.load(open(args.config_file))
            except Exception as e:
                print('ERROR: json.loads()', e)
                exit(1)
        #
        # overwrite attributes in the config with the arguments.
        #
        self.set_opt('server_port', default='18886', opt=args.server_port)
        self.set_opt('server_addr', default='', opt=args.server_addr)
        self.set_opt('doc_root', default='.', opt=args.doc_root)
        self.set_opt('ch_root', type=int, default=0, opt=args.ch_root)
        self.set_opt('log_file', default="stdout", opt=args.log_file)
        self.set_opt('cert_file', default=None, opt=args.cert_file,
                     required=False)
        self.set_opt('ssl_ver', type=int, default=PROTOCOL_TLSv1,
                     opt=args.ssl_ver)
        #
        # fixed self.config['debug_level'] for the logging module.
        #
        loglvl_table = [ logging.INFO, logging.DEBUG, DEBUG2, DEBUG3, DEBUG4 ]
        if len(loglvl_table) > self.config['debug_level']:
            self.config['debug_level'] = loglvl_table[self.config['debug_level']]
        else:
            self.config['debug_level'] = DEBUG4
        #
        if self.config['debug_level'] <= logging.DEBUG:
            print("DEBUG: log level = %d" % self.config['debug_level'])
        #
        # initialize the re_list_exclude_files
        #
        if self.config['debug_level'] <= logging.DEBUG:
            print("DEBUG: initializing the list of file excluded.")
        self.config["re_exclude_files"] = []
        for i in self.config.get("exclude_files", []):
            if self.config['debug_level'] <= logging.DEBUG:
                print("DEBUG:  {} is added".format(i))
            self.config["re_exclude_files"].append(re.compile(i))
        #
        #
        self.configured = True

    def run(self):
        self.set_config()
        self.__set_logger(self.config['log_file'], self.config['debug_level'])

        # change root.
        # XXX needs to disable GET method.
        if self.config['ch_root']:
            try:
                os.chroot(opt['root_dir'])
            except Exception as e:
                print('ERROR:', e)
                exit(1)
        # start the server.
        try:
            httpd = ThreadedHTTPServer((self.config['server_addr'],
                                       int(self.config['server_port'])),
                                       self.handler,
                                       config=self.config)
            if self.config["cert_file"]:
                httpd.socket = logging_ssl_socket(httpd.socket,
                                           server_side=True,
                                           certfile=self.config["cert_file"],
                                           ssl_version=self.config["ssl_ver"],
                                           logger=self.logger)
            # XXX make it a daemon
            sa = httpd.socket.getsockname()
            self.logger.info("Starting HTTP{} server on {} port {}".format(
                             "S" if self.config["cert_file"] else "",
                             sa[0], sa[1]))
            httpd.serve_forever()
        except KeyboardInterrupt as e:
            self.logger.info('\nterminated by keyboard interrupted.')
        except Exception as e:
            self.logger.error(e)
        finally:
            httpd.socket.close()

'''
main
'''
if __name__ == '__main__' :
    httpd = TinyHTTPServer(TinyHTTPHandler)
    httpd.run()

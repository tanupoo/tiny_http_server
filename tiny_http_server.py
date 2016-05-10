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

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading

__version__ = '0.1'

#
# XXX don't publish the path in this server, use self.path instead.
#

class TinyHTTPHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    server_version = 'TinyHTTPServer/' + __version__

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
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _is_debug(self, level):
        if self.server.config['debug_level'] >= level:
            return True
        else:
            return False

    def set_server_version(self, name):
        self.server_version = name

    def file_provider(self):
        ''' file provider.

        @return False something error happened.
        @return True a file was provided.
        '''
        # simply checking self.path.
        # should check it more.
        re_2dot = re.compile('\.\.')
        if re_2dot.search(self.path):
            self.send_error_msg(400, 'ERROR: ".." in the path is not allowed.')
            return False
        # check whether the file exists.
        path = self.server.config['doc_root'] + self.path
        try:
            mode = os.stat(path).st_mode
            if not S_ISREG(mode):
                self.send_error_msg(400, 'ERROR: not a regular file, %s' %
                                    self.path)
                return False
        except Exception as e:
            self.send_error_msg(400, 'ERROR: internal error, %s' % e)
            return False
        self.send_doc(path)
        return True

    def pre_process(self):
        ''' pre-processing to read the content

        it may be overridden.
        access control should be here.
        '''
        if self._is_debug(2):
            print('DEBUG: thread#=', threading.currentThread().getName())
            print('DEBUG: client =', self.client_address)
            print('DEBUG: request=',
                  self.command, self.path, self.request_version)
            if self._is_debug(3):
                print('---BEGIN OF REQUESTED HEADER---')
                print('\n'.join(
                        ['%s: %s' % (k,v) for k,v in self.headers.items()]))
                print('---END OF REQUESTED HEADER---')

    def read_content(self):
        ''' read message
        
        may be overridden. '''
        if self.headers.has_key('Content-Length'):
            self.post_read(self.read_length())
        else:
            self.post_read('')

    def read_length(self):
        ''' read message by the content-length. '''
        if not self.headers.has_key('Content-Length'):
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
        if self._is_debug(3):
            print('---BEGIN OF REQUESTED DATA---')
            print(contents)
            print('---END OF REQUESTED DATA---')
        self.put_response(contents)

    def put_response(self, contents, ctype='text/html'):
        ''' make a list of messages.

        may be overriddedn.
        it is allowed that contents is a list or a string.
        '''
        #
        # just echo the headers and body requested the peer.
        #
        msg_list = []
        msg_list.append(' '.join(
                [self.command, self.path, self.request_version]))
        msg_list.append('\n')
        msg_list.extend(['%s: %s\n' % (k,v) for k,v in self.headers.items()])
        msg_list.append('\n\n')
        if contents:
            msg_list.extend(contents)
        #
        #self.send_once(''.join(msg_list), ctype=ctype)
        size = reduce(lambda a, b: a + len(b), msg_list, 0)
        self.send_once(contents, size, ctype=ctype)

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
                self.wfile.write(i)
        except Exception as e:
            self.send_error_msg(404, 'ERROR: internal error, %s' % e)
            return
        if self._is_debug(3):
            print('---BEGIN OF RESPONSE---')
            print('ctype=', ctype, 'size=', size)
            print('---END OF RESPONSE---')

    def send_error_msg(self, code, content):
        self.log_error(content)
        self.send_error(code, content)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(content)

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
        try:
            if self.file_provider():
                return
        except Exception:
            #contents = '\n'.join(
            #        ['%s: %s' % (k,v) for k,v in self.headers.items()])
            if self.path == '/debug':
                contents = ['%s: %s' % (k,v) for k,v in self.headers.items()]
                self.put_response(contents)
            else:
                self.send_error_msg(404, 'ERROR: no such file %s' % self.path)

    def do_POST(self):
        self.pre_process()
        self.read_content()

    def do_PUT(self):
        self.pre_process()
        self.read_content()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    def __init__(self, server_address, RequestHandlerClass, config=None):
        self.config = config
        HTTPServer.__init__(self, server_address, RequestHandlerClass)

class TinyHTTPServer():

    def __init__(self, handler):
        self.handler = handler

    def __parse_args(self):
        p = argparse.ArgumentParser()
        p.add_argument('-s', action='store', dest='server_addr', default='',
                       help='specifies the address of the server')
        p.add_argument('-p', action='store', dest='server_port',
                       default='18886',
                       help='specifies the port number of the server')
        p.add_argument('-c', action='store', dest='config_file', default=None,
                       help='specifies the name of the configuration file')
        p.add_argument('-D', action='store', dest='doc_root', default=None,
                    help='specifies the directory name of the document root.')
        p.add_argument('-C', action='store', dest='root_dir', default=None,
                       help='specifies the directory name for chroot().')
        p.add_argument('-d', action='append_const', dest='_f_debug',
                       default=[], const=1, help="increase debug mode.")
        p.add_argument('--debug', action='store', dest='_debug_level',
                       default=0, help="specify a debug level.")

        args = p.parse_args()
        args.debug_level = len(args._f_debug) + int(args._debug_level)

        return args

    def run(self):
        opt = self.__parse_args()
        port = int(opt.server_port)
        if (opt.config_file):
            try:
                config = json.loads(open(opt.config_file).read())
            except Exception as e:
                print('ERROR: json.loads()', e)
                exit(1)
        else:
            config = { 'debug_level': 0 }
        # set proper debug_level.
        if opt.debug_level:
            config['debug_level'] = opt.debug_level
        elif not config.has_key('debug_level'):
            config['debug_level'] = 0
        # change directory into the document root..
        if opt.doc_root:
            config['doc_root'] = opt.doc_root
        elif not config.has_key('doc_root'):
            config['doc_root'] = '.'
        # change root.
        try:
            if opt.root_dir:
                os.chroot(opt.root_dir)
        except Exception as e:
            print('ERROR:', e)
            exit(1)
        # start the server.
        try:
            httpd = ThreadedHTTPServer((opt.server_addr, port), self.handler,
                                        config=config)
            # XXX make it a daemon
            sa = httpd.socket.getsockname()
            print('INFO: Starting HTTP server on', sa[0], 'port', sa[1])
            httpd.serve_forever()
        except KeyboardInterrupt as e:
            print('\nterminated by keyboard interrupted.')
        except Exception as e:
            print('ERROR:', e)
        finally:
            httpd.socket.close()

'''
main
'''
if __name__ == '__main__' :
    httpd = TinyHTTPServer(TinyHTTPHandler)
    httpd.run()

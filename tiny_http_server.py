#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import argparse
import traceback
import json
import os
from stat import S_ISREG

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading

__version__ = '0.1'

class TinyHTTPHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    server_version = 'TinyHTTPServer/' + __version__
    max_content_size = 256*1024  # 256KB

    def __init__(self, request, client_address, server, **kwargs):
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
        self.pre_process()
        try:
            mode = os.stat(self.path[1:]).st_mode
            if S_ISREG(mode):
                self.send_doc(200, self.path[1:], 'text/plain')
        except Exception:
            #contents = '\n'.join(
            #        ['%s: %s' % (k,v) for k,v in self.headers.items()])
            if self.path == '/debug':
                contents = ['%s: %s' % (k,v) for k,v in self.headers.items()]
                self.put_response(200, contents)
            else:
                self.send_error_msg(404, 'ERROR: no such file %s' % self.path)

    def do_POST(self):
        self.pre_process()
        self.read_content()

    def do_PUT(self):
        self.pre_process()
        self.read_content()

    def _is_debug(self, level):
        if self.server.config['debug_level'] >= level:
            return True
        else:
            return False

    def set_server_version(self, name):
        server_version = name

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
        length = int(self.headers['Content-Length'])
        if length > self.max_content_size:
            self.send_error_msg(400,
                'ERROR: too large content > %d' % self.max_content_size)
            return None
        return self.read_once(length)

    def read_once(self, length):
        ''' read message with the specified length and return it. '''
        if length:
            return self.rfile.read(length)
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
        self.put_response(200, contents)

    def put_response(self, code, contents, content_type='text/plain'):
        ''' make a list of messages.

        may be overriddedn.
        it is allowed that contents is a list or a string.
        '''
        #
        # make the *body* of the response.
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
        self.send_once(code, msg_list, content_type)

    def send_once(self, code, msg_list, content_type):
        ''' send a list of messages. '''
        self.send_response(code)
        content = ''.join(msg_list)
        self.send_header('Content-Type', content_type)
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)
        if self._is_debug(3):
            print('---BEGIN OF RESPONSE---')
            print(content)
            print('---END OF RESPONSE---')

    def send_error_msg(self, code, content):
        self.log_error(content)
        self.send_error(code, content)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(content)

    def send_doc(self, code, path, content_type):
        ''' send a file.

        @param path path to the file name, which is supposed to be existed.
        '''
        try:
            f = open(path)
        except Exception as e:
            self.send_error_msg(404, 'ERROR: no such file %s' % path)
            return
        self.send_response(code)
        self.send_response(200)
        self.end_headers()
        length = 0
        for line in f.readlines():
            length += len(line)
            self.wfile.write(line)
        f.close()
        self.send_header('Content-Type', content_type)
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', length)
        self.end_headers()
        if self._is_debug(3):
            print('---BEGIN OF RESPONSE---')
            print('file length=', length, 'file=', path)
            print('---END OF RESPONSE---')


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):

    def __init__(self, server_address, RequestHandlerClass, config=None):
        self.config = config
        HTTPServer.__init__(self, server_address, RequestHandlerClass)

class TinyHTTPServer():

    def __parse_args(self):
        p = argparse.ArgumentParser()
        p.add_argument('-s', action='store', dest='server_addr', default='',
                       help='specifies the address of the server')
        p.add_argument('-p', action='store', dest='server_port',
                       default='18886',
                       help='specifies the port number of the server')
        p.add_argument('-c', action='store', dest='config_file', default=None,
                       help='specifies the name of the configuration file')
        p.add_argument('-C', action='store', dest='root_dir', default=None,
                       help='specifies the directory name for chroot().')
        p.add_argument('-d', action='append_const', dest='_f_debug',
                       default=[], const=1, help="increase debug mode.")
        p.add_argument('--debug', action='store', dest='_debug_level',
                       default=0, help="specify a debug level.")

        args = p.parse_args()
        args.debug_level = len(args._f_debug) + int(args._debug_level)

        return args

    def __init__(self, handler):
        self.handler = handler

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
        # change directory.
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

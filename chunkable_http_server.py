#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Shoichi Sakane <sakane@tanu.org>, All rights reserved.
# See the file LICENSE in the top level directory for more details.
#

from __future__ import print_function

import sys
import threading
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn

'''
- Chunk handling referred to "4.1.  Chunked Transfer Coding in RFC 7230".
- As for the processing of 'Connection: close' and 'Connection: Keep-Alive',
  this class doesn't support persistent connection.
  i.e. it always replies with 'connection: close'.
'''

'''
4.1 Chunked Transfer Coding

 chunked-body   = *chunk
                  last-chunk
                  trailer-part
                  CRLF

 chunk          = chunk-size [ chunk-ext ] CRLF
                  chunk-data CRLF
 chunk-size     = 1*HEXDIG
 last-chunk     = 1*("0") [ chunk-ext ] CRLF

 chunk-data     = 1*OCTET ; a sequence of chunk-size octets
'''

__version__ = '0.1'

class ChunkableHTTPRequestHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    server_version = 'ChunkableHTTP/' + __version__

    max_content_size = 512*1024  # 512KB
    force_chunked = False
    chunk_max_size = 512
    chunk_header_length = 128    # chunk header length of inline or footer
    chunk_tail_buffer = 16
    chunk_read_timeout = 5

    def __init__(self, request, client_address, server, **kwargs):
        if kwargs.has_key('force_chunked'):
            if kwargs['force_chunked'] in [ True, False ]:
                self.force_chunked = kwargs['force_chunked']
            else:
                raise ValueError('invalid value of force_chunked')
        if kwargs.has_key('chunk_max_size'):
            if kwargs['chunk_max_size'] > 0:
                self.chunk_max_size = kwargs['chunk_max_size']
            else:
                raise ValueError('invalid value of chunk_max_size')
        if kwargs.has_key('chunk_read_timeout'):
            if kwargs['chunk_read_timeout'] > 0:
                self.chunk_read_timeout = kwargs['chunk_read_timeout']
            else:
                raise ValueError('invalid value of chunk_read_timeout')
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
        '''
        may be overriddedn.
        '''
        self.pre_process()
        self.read_content()

    def do_POST(self):
        '''
        may be overriddedn.
        '''
        self.pre_process()
        self.read_content()

    def pre_process(self):
        ''' pre-processing to read the content

        may be overriddedn.
        '''
        if self.server.debug_level:
            print('DEBUG: thread#=', threading.currentThread().getName())
            print('DEBUG: client =', self.client_address)
            print('DEBUG: request=',
                  self.command, self.path, self.request_version)
            if self.server.debug_level > 1:
                print('---BEGIN OF REQUESTED HEADER---')
                print('\n'.join(['%s: %s' % (k,v) for k,v in self.headers.items()]))
                print('---END OF REQUESTED HEADER---')

    def read_content(self):
        transfer_encoding = self.headers.get('Transfer-Encoding')
        if transfer_encoding:
            if transfer_encoding == 'chunked':
                self.read_chunked()
            else:
                print('ERROR: not supported such transfer_encoding',
                      transfer_encoding)
        elif self.headers.has_key('Content-Length'):
            self.read_length()
        else:
            if self.server.debug_level:
                print('DEBUG: Content-Length or Transfer-Encoding are not specified.')
            self.read_somehow()

    def read_chunked(self):
        transfer_encoding = self.headers.get('Transfer-Encoding')
        if transfer_encoding != 'chunked':
            raise RuntimeError()
        t = threading.Thread(target=self._read_chunked)
        t.start()
        t.join(self.chunk_read_timeout)
        if t.is_alive() == True:
            print('WARNING: timed out of thread of reading chunks.')

    def _read_chunked(self):
        total_length = 0
        contents = []
        while True:
            try:
                #
                # read the 1st line of a chunk.
                #     i.e. chunk-size [ chunk-ext ] CRLF
                # chunk_header_length bytes is enough to read the chunk header.
                #
                chunk_header = self.rfile.readline(self.chunk_header_length)
                if self.server.debug_level:
                    print('DEBUG: chunk header=', chunk_header)
                if chunk_header == '\r\n':
                    if self.server.debug_level:
                        print('DEBUG: last-chunk does not exist.')
                        print('DEBUG: stop reading chunks anyway.')
                    chunk_size = 0
                    break
                if not chunk_header:
                    raise RuntimeError('Connection reset by peer')
                chunk_size_string = chunk_header.split(';', 1)[0]
                chunk_size = int(chunk_size_string, 16)
            except:
                raise
            if chunk_size == 0:
                if self.server.debug_level:
                    print('DEBUG: last-chunk has been found.')
                break
            #
            # read a chunk
            #   don't use readline() because CR or LF may be among the chunk.
            #
            chunk = self.rfile.read(chunk_size)
            if self.server.debug_level:
                print('DEBUG: chunked size=', chunk_size)
                print('DEBUG: chunk=', chunk)
                if self.server.debug_level > 1:
                    print('DEBUG: chunk(hex)=',
                          [hex(x) for x in bytearray(chunk)])
            # remove the tail.
            nl = self.rfile.read(2)
            if self.server.debug_level:
                print('DEBUG: tail of chunk=', [hex(x) for x in bytearray(nl)])
            #
            contents.append(chunk)
            total_length += chunk_size
            if total_length > self.max_content_size:
                raise ValueError('too large content > %d' %
                                 self.max_content_size)
        # cool down
        # XXX just skip the footer and CR+LF in the end.
        while True:
            try:
                footer = self.rfile.readline(self.chunk_header_length)
                if self.server.debug_level:
                    print('DEBUG: footer=', footer)
                if footer == '\r\n':
                    if self.server.debug_level:
                        print('DEBUG: end of chunk has been found.')
                    break
                elif not footer:
                    raise RuntimeError('Connection reset by peer')
            except:
                raise
        self.post_read(contents)

    def read_length(self):
        if not self.headers.has_key('Content-Length'):
            raise RuntimeError()
        length = int(self.headers['Content-Length'])
        if length > self.max_content_size:
            raise ValueError('too large content > %d' %
                                self.max_content_size)
        self.read_once(length)

    def read_once(self, length):
        content = ''
        if length:
            content = self.rfile.read(length)
        self.post_read([content])

    def read_somehow(self):
        '''
        may be overriddedn.
        '''
        self.post_read([])

    def post_read(self, contents):
        ''' post process after it read the whole content.

        may be overriddedn.
        '''
        if self.server.debug_level > 1:
            print('---BEGIN OF REQUESTED DATA---')
            print(contents)
            print('---END OF REQUESTED DATA---')
        self.put_response(200, contents)

    def put_response(self, code, contents, content_type='text/plain'):
        #
        # make the *body* of the response.
        #
        msg_list = []
        msg_list.append(' '.join([self.command, self.path, self.request_version]))
        msg_list.append('\n')
        msg_list.extend(['%s: %s\n' % (k,v) for k,v in self.headers.items()])
        msg_list.append('\n\n')
        msg_list.extend(contents)
        #
        if self.force_chunked:
            self.send_chunked(code, msg_list, content_type)
        else:
            self.send_once(code, msg_list, content_type)

    def send_chunked(self, code, msg_list, content_type):
        self.send_response(code)
        #self.send_header('Content-Type', content_type)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Connection', 'close')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        if self.server.debug_level > 1:
            print('---BEGIN OF RESPONSE---')
        for c in msg_list:
            s = self.chunk_max_size
            bl = len(c) / s + (1 if len(c) % s else 0)
            c_frag = [ c[x * s : x * s + s] for x in range(bl) ]
            for i in c_frag:
                chunk_size = hex(len(i))[2:]
                self.wfile.write(''.join([ chunk_size, '\r\n', i, '\r\n' ]))
                if self.server.debug_level > 1:
                    print(chunk_size)
                    print(i.strip(), '\n')
                    if self.server.debug_level > 2:
                        print('hex=', [ hex(x)[2:] for x in bytearray(i) ],
                              '\n')
        if self.server.debug_level > 1:
            print('---END OF RESPONSE---')
        self.wfile.write('0\r\n')
        self.wfile.write('\r\n')
        # 
        self.send_header('Connection', 'close')

    def send_once(self, code, msg_list, content_type):
        self.send_response(code)
        content = ''.join(msg_list)
        print([hex(ord(x)) for x in content[-4:]])
        self.send_header('Content-Type', content_type)
        self.send_header('Connection', 'close')
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)
        if self.server.debug_level > 1:
            print('---BEGIN OF RESPONSE---')
            print(content)
            print('---END OF RESPONSE---')

class ChunkableHTTPServer(ThreadingMixIn, HTTPServer):
    '''Handle requests in a separate thread.'''

    def __init__(self, server_address, RequestHandlerClass, debug_level=0):
        self.debug_level = debug_level
        HTTPServer.__init__(self, server_address, RequestHandlerClass)

if __name__ == '__main__':
    ''' Test the Chunkable HTTP handler class.

    This runs an HTTP server on port 8080 (or the first command line argument).
    The second parameter specifies the debug level.  (default is zero)
    '''
    server_address = ('', 8080)
    debug_level = 0
    if len(sys.argv) > 1:
        server_address = ('', int(sys.argv[1]))
    if len(sys.argv) > 2:
        debug_level = int(sys.argv[2])

    httpd = ChunkableHTTPServer(server_address, ChunkableHTTPRequestHandler,
                               debug_level=debug_level)

    sa = httpd.socket.getsockname()
    print('Serving HTTP on', sa[0], 'port', sa[1], '....')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt as e:
        print('\nterminated by keyboard interrupted.')


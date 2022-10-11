"""
- CS2911 - 011
- Fall 2022
- Lab 4 - HTTP Client
- Names:
  - Hudson Arney
  - Josh Sopa

An HTTP client

Introduction: (Describe the lab in your own words)




Summary: (Summarize your experience with the lab, what you learned, what you liked,what you disliked, and any suggestions you have for improvement)





"""

import socket
import re
import ssl


def main():
    """
    Tests the client on a variety of resources
    """

    # These resource request should result in "Content-Length" data transfer
    get_http_resource('https://www.httpvshttps.com/check.png', 'check.png')

    # this resource request should result in "chunked" data transfer
    #get_http_resource('https://www.httpvshttps.com/', 'index.html')

    # this resource request should result in "chunked" data transfer
    # get_http_resource('https://www.youtube.com/', 'youtube.html')

    # If you find fun examples of chunked or Content-Length pages, please share them with us!


def get_http_resource(url, file_name):
    """
    Get an HTTP resource from a server
           Parse the URL and call function to actually make the request.
    :param url: full URL of the resource to get
    :param file_name: name of file in which to store the retrieved resource
    (do not modify this function)
    """

    protocol = 'https'
    default_port = 443

    # Parse the URL into its component parts using a regular expression.
    if not url.startswith('https://'):
        print('Request URL must start with https://')
        return

    url_match = re.search(protocol + '://([^/:]*)(:\d*)?(/.*)', url)
    url_match_groups = url_match.groups() if url_match else []
    #    print 'url_match_groups=',url_match_groups
    if len(url_match_groups) == 3:
        host_name = url_match_groups[0]
        host_port = int(url_match_groups[1][1:]) if url_match_groups[1] else default_port
        host_resource = url_match_groups[2]
        print('host name = {0}, port = {1}, resource = {2}'.
              format(host_name, host_port, host_resource))
        status_string = do_http_exchange(host_name, host_port,
                                         host_resource, file_name)
        print('get_http_resource: URL="{0}", status="{1}"'.format(url, status_string))
    else:
        print('get_http_resource: URL parse failed, request not sent')


def setup_connection(host, port):
    """
    Sets up the TCP connection to the given host at the given port using HTTPS (TLS)
    :param str host: host name to connect to
    :param int port: port number for the connection
    :return: TCP socket
    (do not modify this function)
    """

    # Set up the TCP connection
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((host, port))

    # Wrap the socket in an SSL connection
    context = ssl.create_default_context()
    ssl_socket = context.wrap_socket(tcp_socket, server_hostname=host)
    tcp_socket.close()

    # Return the socket
    return ssl_socket


def do_http_exchange(host, port, resource, file_name):
    """
    Get an HTTP resource from a server
    :param str host: the ASCII domain name or IP address of the server machine (i.e., host) to connect to
    :param int port: port number to connect to on server host
    :param str resource: the ASCII path/name of resource to get. This is everything in the URL after the domain name,
           including the first /.
    :param file_name: string (str) containing name of file in which to store the retrieved resource
    :return: the status code
    :rtype: int
    """

    # Setup the TCP connection
    tcp_socket = setup_connection(host, port)
    resource = resource.encode('ASCII')
    host = host.encode('ASCII')
    request = b'GET ' + resource + b' HTTP/1.1\x0d\x0a' \
                                   b'Host: ' + host + b'\x0d\x0a' \
                                                      b'\x0d\x0a'
    # Request the resource and write the data to the file
    tcp_socket.sendall(request)

    header = parse_header(tcp_socket)
    next_byte(tcp_socket)
    if b'Content-Length' in header:
        create_file(parse_body(tcp_socket, False, header[b'Content-Length']), file_name)
    else:
        create_file(parse_body(tcp_socket, True, 0), file_name)

    return 500  # Replace this "server error" with the actual status code


def parse_header(data_socket):
    dictionary = read_first_line(data_socket)
    header = read_header(data_socket, dictionary)
    return header


def read_header(data_socket, header):
    data = b''

    # Stops when header is done
    index = 0
    while data != b'\x0d':

        while data != b'\x0a':
            # Stops when line is done
            key = b''
            value = b''
            if index == 0:
                data = next_byte(data_socket)
            while data != b':':
                # Get key
                key += data
                data = next_byte(data_socket)

            # Read 20 in ascii (space)
            data = next_byte(data_socket)

            data = next_byte(data_socket)
            while data != b'\x0d':
                # Get key
                value += data
                data = next_byte(data_socket)

            # Read 0f value to exit loop
            data = next_byte(data_socket)
            header[key] = value

        index += 1
        data = next_byte(data_socket)

    return header


def read_first_line(data_socket):
    line = dict()

    typ = get_version(data_socket)
    line['version'] = typ

    # get status
    data = next_byte(data_socket)
    status = b''
    while data != b'\x20':
        status += data
        data = next_byte(data_socket)
    line['status'] = status

    # get ok status
    data = next_byte(data_socket)
    ok = b''
    while data != b'\x0d':
        ok += data
        data = next_byte(data_socket)
    line['ok'] = ok

    # read line feed
    next_byte(data_socket)

    return line


def get_version(data_socket):
    typ = b''
    data = next_byte(data_socket)
    while data != b'\x20':
        typ += data
        data = next_byte(data_socket)
    return typ


# When the data is chunked we only take the data socket because
# there is no content-length for the size
def parse_chunking(data_socket):
    # new blank byte object
    chunked_data = b''
    size = b''
    # data that will be compared in the loop to see when the body reaches the end of the message
    data = next_byte(data_socket)
    # goes until it reaches b'\x0d\x0a\x0d\x0a'
    while data != b'0':
        while data != b'\x0d':
            size += data
            data = next_byte(data_socket)
        size = size.decode('ASCII')
        size = int(size, 16)
        size = int(size)
        # read line feed
        data = next_byte(data_socket)
        print(data)
        print(size)
        for x in range(size):
            # checks the next byte that will be compared to later
            data = next_byte(data_socket)
            # adds the data to the blank byte and continues to do so in the loop
            chunked_data += data
        # read 0d 0a
        data = next_byte(data_socket)
        data = next_byte(data_socket)
        # read next size
        data = next_byte(data_socket)

    #read 0d 0a
    data = next_byte(data_socket)
    data = next_byte(data_socket)

    return chunked_data



#    data_length = int.from_bytes(next_byte(data_socket), 'big') + int.from_bytes(next_byte(data_socket), 'big')

# As long as the body header isn't equal to CRLF, CRLF it will copy down the message size
#    while data_length > 0:
#       body_data += next_byte(data_socket)
#       data_length -= data_length

#    for body_size in range(0, int.from_bytes(body_data, 'big')):
#       body_message += next_byte(data_socket)


# If the message is unchunked it uses the socket and size (from the content length in the header)
def read_body(data_socket, size):
    # body data is the data received from the socket that checks each byte from the message body
    body_data = data_socket.recv(int.from_bytes(size, 'big'))
    print(body_data)
    # returns the received data
    return body_data


# Checks if the body of message is chunked or not, this will then call the right method
# based on if the message is chunked or unchunked
def parse_body(data_socket, chunked, size):
    # if the message is chunked
    if chunked:
        return parse_chunking(data_socket)
    else:
        # if the message is unchunked
        return read_body(data_socket, size)


def create_file(message, number):
    text_file = open(number, "wb")
    text_file.write(message)
    text_file.close()


def next_byte(data_socket):
    """
    Read the next byte from the socket data_socket.

    Read the next byte from the sender, received over the network.
    If the byte has not yet arrived, this method blocks (waits)
      until the byte arrives.
    If the sender is done sending and is waiting for your response, this method blocks indefinitely.

    :param data_socket: The socket to read from. The data_socket argument should be an open tcp
                        data connection (either a client socket or a server data socket), not a tcp
                        server's listening socket.
    :return: the next byte, as a bytes object with a single byte in it
    """
    return data_socket.recv(1)


# Define additional functions here as necessary
# Don't forget docstrings and :author: tags


main()

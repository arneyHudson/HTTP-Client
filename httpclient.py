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
    get_http_resource('https://www.httpvshttps.com/','index.html')

    # this resource request should result in "chunked" data transfer
    #get_http_resource('https://www.youtube.com/', 'youtube.html')

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

    # Request the resource and write the data to the file

    # Don't forget to close the tcp_socket when finished
 
    return 500  # Replace this "server error" with the actual status code

# Define additional functions here as necessary
# Don't forget docstrings and :author: tags


main()

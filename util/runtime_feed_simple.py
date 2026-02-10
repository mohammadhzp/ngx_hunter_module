import sys
import ipaddress
import socket

host = "127.0.0.1"
port = 8889


def module_help(just_op_type=False):
    if not just_op_type:
        print("Usage:")
        print("python3 {} operation_type IP\n".format(file_name))

    print('Operation type is one of the followings')

    print('\ta4: Add IpV4')
    print('\ta6: Add IpV6')
    print('\td4: Remove IpV4')
    print('\td6: Remove IpV6')

    if not just_op_type:
        print("Example:")
        print("python3 {} a4 127.0.0.1".format(file_name))


def ip_handler(ip):
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError as e:
        print(e)
        return False

    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip_handler(ip.ipv4_mapped)

    return ip.packed


file_name = __file__.split('/')[-1]
arguments = sys.argv[1:]
if '-h' in arguments or '--help' in arguments:
    module_help()
    sys.exit()

try:
    _kind = arguments[0]
    _ip = arguments[1]
except(IndexError, ValueError, TypeError):
    print('Wrong usage')
    module_help()
    sys.exit()


if _kind not in ['a4', 'a6', 'd4', 'd6']:
    print('Wrong Type operation provided')
    module_help(True)
    sys.exit()


_packed = ip_handler(_ip)
if _packed is False:
    print('Invalid IP provided')
    sys.exit()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

s.sendall(_kind.encode() + _packed + b"done")
print('Request sent, waiting for the result: ')

result = s.recv(8).decode('utf8')
s.close()

if result > '0':
    print('Operation successfully completed -> {}'.format(result))
else:
    print('Operation failed, error code: -> {}'.format(result))

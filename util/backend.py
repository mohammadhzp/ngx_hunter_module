from typing import Optional
import sys
import socket
import ipaddress
import pymysql.cursors

sock: Optional[socket.socket] = None
db: Optional[pymysql.Connection] = None
ip_version_delimiter = b"!!!!"

addr = ('127.0.0.1', 6981)


def prepare_socket(for_test=False):
    global sock
    if sock is not None:
        try:
            sock.shutdown(2)
            sock.close()
        except Exception as e:
            print(e)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if for_test:
        sock.connect(addr)
        return

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(addr)
    sock.listen(8)


def ip_handler(ip):
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip_handler(ip.ipv4_mapped)
    return ip.packed


def get_source():
    return (
        ip_handler('127.0.0.1'),
        ip_handler('111.222.52.32'),
        ip_handler('66.38.64.22'),
    )


def prepare_ips():
    data = dict(v4=[], v6=[])
    ips = list(get_source())
    if len(ips) == 0:
        return data

    for ip in ips:
        if ip is False:
            continue

        if len(ip) == 4:
            data['v4'].append(ip)
        else:
            data['v6'].append(ip)

    return data


def run_test():
    length = 4
    family = socket.AF_INET
    no_ips = 0

    try:
        while no_ips < 5:
            ip = sock.recv(length)
            if ip == ip_version_delimiter:
                length = 16
                family = socket.AF_INET6
                continue
            if ip == b'':
                no_ips += 1
                continue

            print(socket.inet_ntop(family, ip))
    except Exception as e:
        print(e)


def run():
    ips = prepare_ips()
    if len(ips['v4']) > 0:
        for v4 in ips['v4']:
            connection.send(v4)

    connection.send(ip_version_delimiter)

    if len(ips['v6']) > 0:
        for v6 in ips['v6']:
            connection.send(v6)


try:
    sys.argv.remove('test')
except ValueError:
    prepare_socket()
else:
    prepare_socket(True)
    run_test()
    try:
        sock.shutdown(2)
        sock.close()
    except Exception as _e:
        print(_e)
    sys.exit()


r = 0
while True:
    r += 1
    print("Started round", r)

    try:
        connection, address = sock.accept()
    except KeyboardInterrupt:
        break

    try:
        run()
        connection.shutdown(2)
        connection.close()
    except Exception as _e:
        print(_e)

sock.shutdown(2)
sock.close()

print("Done")

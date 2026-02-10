import asyncio
import socket


class Protocol(asyncio.Protocol):
    data = b''

    def data_received(self, data):
        self.data += data

    def eof_received(self):
        op = self.data[:2]
        ips = self.data[2:]

        while True:
            ip = ips[:4]
            if ip == b'done':
                break

            print(f'{op}:', socket.inet_ntop(socket.AF_INET, ip))
            ips = ips[4:]

        print('Done')


async def run():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(Protocol, family=socket.AF_INET, host='127.0.0.1', port=5146)

    try:
        await asyncio.Event().wait()

    finally:
        server.close()
        await server.wait_closed()


try:
    asyncio.run(run())

except KeyboardInterrupt:
    pass

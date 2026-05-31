#!/usr/bin/env python3
import asyncio
import struct
import random
import time
import datetime

class QuaboEmulatorProtocol(asyncio.DatagramProtocol):
    def __init__(self, quabo_id, means, variances):
        self.quabo_id = quabo_id
        self.means = means
        self.stds = [v**0.5 for v in variances]
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        recv_time = datetime.datetime.now().strftime('%H:%M:%S.%f')
        if not data:
            return

        cmd = data[0]
        # Command 0x0c is "Read SW PH packets"
        if cmd == 0x0c:
            print(f"[{recv_time}] Quabo {self.quabo_id}: Received R-PH command from {addr}")
            
            # Generate 256 Gaussian values
            pixels = []
            for m, s in zip(self.means, self.stds):
                val = int(random.gauss(m, s))
                # Clamp to signed 16-bit range just in case
                val = max(-32768, min(32767, val))
                pixels.append(val)
            
            # Response: 1 byte cmd, 3 bytes reserved, 512 bytes pixel data
            header = struct.pack('B', 0x0c) + b'\x00' * 3
            pixel_data = struct.pack('<256h', *pixels) # 'h' is signed 16-bit
            
            self.transport.sendto(header + pixel_data, addr)
        else:
            print(f"[{recv_time}] Quabo {self.quabo_id}: Received unknown command 0x{cmd:02x}")

async def run_emulator(quabo_id, port):
    # Initialize 256 channels with random mean (0-10) and variance (10-20)
    means = [random.uniform(0, 10) for _ in range(256)]
    variances = [random.uniform(10, 20) for _ in range(256)]
    
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QuaboEmulatorProtocol(quabo_id, means, variances),
        local_addr=('127.0.0.1', port)
    )
    print(f"Quabo {quabo_id} emulator listening on 127.0.0.1:{port}")
    
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        transport.close()

async def main():
    # Start 4 emulators for ports 60000 to 60003
    tasks = []
    for i in range(4):
        tasks.append(run_emulator(i, 60000 + i))
    
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    if hasattr(asyncio, 'run'):
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            print("\nShutting down emulator...")
    else:
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(main())
        except KeyboardInterrupt:
            print("\nShutting down emulator...")
        finally:
            loop.close()

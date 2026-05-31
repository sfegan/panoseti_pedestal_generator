#!/usr/bin/env python3
import asyncio
import struct
import random
import time
import datetime
import argparse

class QuaboEmulatorProtocol(asyncio.DatagramProtocol):
    def __init__(self, quabo_id, means, variances, delay=0.1):
        self.quabo_id = quabo_id
        self.means = means
        self.stds = [v**0.5 for v in variances]
        self.delay = delay
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
            # Schedule the delayed response
            asyncio.ensure_future(self.send_delayed_response(addr))
        else:
            print(f"[{recv_time}] Quabo {self.quabo_id}: Received unknown command 0x{cmd:02x}")

    async def send_delayed_response(self, addr):
        if self.delay > 0:
            await asyncio.sleep(self.delay)
            
        # Generate 256 Gaussian values
        pixels = []
        for m, s in zip(self.means, self.stds):
            val = int(random.gauss(m, s))
            val = max(-32768, min(32767, val))
            pixels.append(val)
        
        header = struct.pack('B', 0x0c) + b'\x00' * 3
        pixel_data = struct.pack('<256h', *pixels)
        self.transport.sendto(header + pixel_data, addr)

async def run_emulator(quabo_id, port, delay):
    # Initialize 256 channels with random mean (0-10) and variance (10-20)
    means = [random.uniform(0, 10) for _ in range(256)]
    variances = [random.uniform(10, 20) for _ in range(256)]
    
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QuaboEmulatorProtocol(quabo_id, means, variances, delay),
        local_addr=('127.0.0.1', port)
    )
    print(f"Quabo {quabo_id} emulator listening on 127.0.0.1:{port} (delay={delay}s)")
    
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        transport.close()

async def main():
    parser = argparse.ArgumentParser(description='PANOSETI Quabo Emulator')
    parser.add_argument('--delay', type=float, default=0.001, help='Response delay in seconds')
    parser.add_argument('--disable', type=int, nargs='*', default=[], help='List of quabo IDs (0-3) to disable')
    args = parser.parse_args()

    # Start 4 emulators for ports 60000 to 60003
    tasks = []
    disabled_ids = set(args.disable)
    for i in range(4):
        if i in disabled_ids:
            print(f"Quabo {i} is DISABLED.")
            continue
        tasks.append(run_emulator(i, 60000 + i, args.delay))
    
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

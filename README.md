# PANOSETI Pedestal Generator

This repository contains a tool to trigger and capture pedestal events from PANOSETI detector modules:
- `capture_pedestal_events.py`: Polls detector boards (Quabos) for software-generated Pulse Height pedestals events, wraps the payloads in Ethernet/IP/UDP headers, and writes them to a `.pcapng` file.
- `quabo_emulator.py`: Emulates four Quabo boards responding to SW PH trigger commands with normal-distributed random pixel values for testing.

Author: Stephen Fegan <sfegan@llr.in2p3.fr> (2026-05-30)
Laboratoire Leprince-Ringuet, CNRS/IN2P3, Ecole Polytechnique, Institut Polytechnique de Paris

AI usage: Gemini-CLI

---

## Pedestal Events

Pedestal events sample the baseline pixel amplitudes when no trigger is present. These can be used downstream to estimate the average baseline per pixel and its variance. These are used in a gamma-ray analysis to subtract the baseline during pulse analysis and to fit the pointing model based on the contribution of starlist to the pixel variance. Externally generated pedestal events improve the measurement of these values by increasing the sampling to any desired rate, independent of the actual trigger rate of the system.

---

## How It Works

`capture_pedestal_events.py` polls a module of four Quabo boards (each processing 256 pixels), records the responses, and writes them to a `.pcapng` file for offline analysis. The script is designed to run at low frequencies during an observation, or at high frequencies (up to 1000 Hz) for dedicated calibration runs.

### 1. Timing and Scheduling

The script uses a software-based phase-locked loop to schedule polling times relative to the system clock. It supports both high frequencies and fractional frequencies (periods > 1s). Triggers are scheduled at:
$$\text{Trigger Time} = \text{Epoch} + (\text{Slot} \times \text{Period}) + \text{Offset}$$
where:
*   $\text{Period}$ is derived from `--frequency` (supports negative integers for $1/n$ Hz).
*   $\text{Offset} = 0.5 \times \min(\text{Period}, 1.0)$.

This ensures that for high frequencies, triggers occur in the middle of each time slot, while for fractional frequencies (periods $\ge 1$s), triggers are anchored at exactly $0.5$ seconds into the first second of the polling cycle.

### 2. UDP Polling
In each cycle, the script sends the 64-byte software read command (`R_PH`: first byte `0x0c` followed by zeros) to the four configured quabo boards concurrently. It waits for responses from the quabos which contain the measured PH data. These are matched to pending requests using the quabo's `(IP, Port)` address and matched packets are given the same sequence number and event time for tracking. If a response is not received within the specified timeout, the quabo is marked as "dropped" for that cycle, which is logged in the diagnostics.

### 3. Packet Format & Repacking
Raw response packets from the quabos contain a 4-byte header and 512 bytes of pixel data (256 channels of 16-bit signed integers). The script repacks this data into a 528-byte PANOSETI Science Packet:

| Offset (Bytes) | Size | Field Name | Value / Description |
| :--- | :--- | :--- | :--- |
| `0` | 1B | `acq_mode` | `0x01` (Pulse Height) |
| `1` | 1B | `packet_ver` | `1` (16-bit signed PH) |
| `2` | 2B | `packet_no` | 16-bit sequence number (Little-Endian) |
| `4` | 2B | `boardloc` | Location ID: `(Module ID << 2) \| Quadrant` |
| `6` | 4B | `TAI` | TAI seconds since epoch (`UTC + tai_offset`) |
| `10` | 4B | `NANOSEC` | Sub-second trigger time in nanoseconds |
| `14` | 2B | *Reserved* (or `Flags`?) | 0x0001 |
| `16` | 512B | `pixel_data` | 256 pixel values (16-bit signed integers; or are these unsigned.. to be determined?) |

**Note:** I propose that the *Reserved* field be considered as a *Flags* field in the future, allowing for future expansion without breaking compatibility. Here I propose that bit 0 (LSB) be used to indicate whether the payload contains a software triggered event.

### 4. Ethernet/IP/UDP Encapsulation
The 528-byte science payload is wrapped in mock network headers to match packets that have been captured with Wireshark (Total size: 570 bytes).
* **Ethernet II Header** (14 bytes): Source/Dest MAC set to zero. EtherType `0x0800`.
* **IPv4 Header** (20 bytes): Quabo IP as source, DAQ IP as destination.
* **UDP Header** (8 bytes): Port `60001` for source and destination.
* **Checksums**: By default, IP and UDP checksums are set to zero. Full checksum calculation can be enabled via `--compute-checksums`.

### 5. PCAPNG file output (`PcapngWriter`)
To emulate the handling of the science packets from normal, triggered events, the pedestal packets are written to a `.pcapng` file using the internal `PcapngWriter` class, which handles writing the various PCAPNG header blocks. The output file is named according to the template specified by `--output` (default: `pedestals_{scope}_{date}_{time}.pcapng`), where:
* `{scope}` is the site name (e.g. `Gattini`, `Winter`, `Fern` or `PTI`).
* `{date}` is the current date in `YYYYMMDD` format.
* `{time}` is the current time in `HHMMSS` format.
* **Rollover**: Files roll over after `--rollover` seconds. Setting `--rollover 0` disables rotation, using a single file for the entire session.

### 6. Diagnostics and Monitoring
* **Watchdog**: Logs a summary every 60 seconds including:
    * Number of pedestal events generated.
    * **Dropped Cycles**: Indicates if the script is falling behind (CPU/OS bottleneck).
    * **Missing Packets**: Tracks packet loss per Quabo (Network bottleneck).
* **Logging**: the logging level of the Python logger can be adjusted via the `--log-level` argument.

---

## Site Configurations

Presets configure the Quabo IP addresses, DAQ IP address, and module ID:
* For physical sites, Quabo boards are assumed to have sequential IP addresses starting from `base_ip` (Quadrant 0 to 3) on port `60000`.
* For `localhost`, all four boards run on `127.0.0.1` using ports `60000` to `60003`.

The IP addresses and ports can be overridden with the `--quabos` argument for custom setups or testing.

| Preset | Site Name | Base IP | DAQ IP | Module ID | Mode |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gattini` | Gattini | `192.168.3.248` | `192.168.0.4` | `254` | Sequential IPs |
| `winter` | Winter | `192.168.3.244` | `192.168.0.6` | `253` | Sequential IPs |
| `fern` | Fern | `192.168.3.240` | `192.168.0.9` | `252` | Sequential IPs |
| `pti` | PTI | `192.168.3.232` | `192.168.0.8` | `250` | Sequential IPs |
| `localhost` | Emulator | `127.0.0.1` | `127.0.0.1` | `0` | Sequential Ports |

---

## Command Line Arguments

| Argument | Shorthand | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--site` | `-s` | *String* | **Required** | Preset choice (`gattini`, `winter`, `fern`, `pti`, `localhost`) |
| `--frequency` | | *Int* | `1` | Frequency in Hz (-1000-1000). Use negative integers for $1/n$ Hz (e.g. `-2` = 0.5 Hz). |
| `--rollover` | | *Int* | `600` | Rollover interval in seconds (0 to disable) |
| `--pcap-output` | `-o` | *String* | `pedestals_{scope}_{date}_{time}.pcapng` | Output path template for PCAP |
| `--pff-output` | | *String* | `start_{isotime}.dp_ped1024.bpp_2.module_{module}.seqno_{seqid}.pff` | Output path template for PFF |
| `--tai-offset` | | *Int* | `37` | TAI offset from UTC in seconds |
| `--data-port` | | *Int* | `0` | Local port to bind for data (0 for random) |
| `--command-port` | | *Int* | `0` | Port for control commands (0 to disable) |
| `--pcap-buffer` | | *Int* | *Dynamic* | Packets to buffer before write (Default: 60 or frequency) |
| `--compute-checksums` | | *Flag* | `False` | Enable IP/UDP checksum calculation |
| `--log-level` | | *String* | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `--log-file` | | *String* | `None` | Optional file to write log messages to |
| `--timeout` | | *Float* | `None` | UDP timeout in seconds (default: $0.5 \times \min(\text{Period}, 1.0)$) |
| `--quabos` | | *List* | `None` | Overrides site defaults with specific `host[:port]` |

---

## Command Port

If `--command-port` is set to a non-zero value, the script listens for UDP commands. 

- **STOP**: Sending the string `STOP` to the command port will cause the script to signal a shutdown.
- **Response**: The script responds with `STOPPING` to the sender.
- **Termination**: Upon receiving `STOP`, the main run loop terminates immediately.
- **Grace Period**: The script waits for 5 seconds after the main loop has stopped before finally closing the command port and exiting. This allows for the `STOPPING` response to be resent if the original command is repeated (e.g., if the sender didn't receive the response).

---

## Running Locally

To test the capture utility locally using the emulator:

### 1. Start the Emulator
Run the emulator to simulate four Quabo boards on `127.0.0.1` listening on ports `60000` to `60003`:
```bash
python3 quabo_emulator.py --delay 0.001
```

### 2. Start the Capture Utility
```bash
python3 capture_pedestal_events.py --site localhost --frequency 1000
```

## References:

- [PANOSETI quabo packet interface](https://github.com/panoseti/panoseti/wiki/Quabo-packet-interface)
- [PANOSET control_quabo.py test script](https://github.com/panoseti/panoseti/blob/master/control/test_scripts/control_quabo.py) (see "R-PH" command handling)
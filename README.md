# PANOSETI Pedestal Generator

This repository contains a tool to trigger and capture pedestal events from PANOSETI detector modules:
- `capture_pedestal_events.py`: Polls detector boards (Quabos) for software-generated Pulse Height pedestals events, wraps the payloads in Ethernet/IP/UDP headers, and optionally writes them to disk.
- `quabo_emulator.py`: Emulates four Quabo boards responding to SW PH trigger commands with normal-distributed random pixel values for testing.

Author: Stephen Fegan <sfegan@llr.in2p3.fr> (2026-05-30)
Laboratoire Leprince-Ringuet, CNRS/IN2P3, Ecole Polytechnique, Institut Polytechnique de Paris

AI usage: Gemini-CLI

---

## Pedestal Events

Pedestal events sample the baseline pixel amplitudes when no trigger is present. These can be used to estimate the average baseline per pixel and its variance. These are used in a gamma-ray analysis to subtract the baseline during pulse analysis and to fit the pointing model based on the contribution of starlight to the pixel variance. Externally generated pedestal events improve the measurement of these values by increasing the sampling to any desired rate, independent of the actual trigger rate of the system.

This utility is designed to poll the Quabo boards with software-generated triggers at a user-defined frequency to capture pedestal events. It can be run during normal observations at low frequencies (e.g. 1 Hz) to continuously monitor the pedestal values during a run. 

**Note:** In PANOSETI, in the nominal acquisition mode, the Quabo boards automatically subtract an estimate of the baseline from the measured values for on-sky triggers and return the resulting value as a signed integer. The baselines are astimated from a series of baseline measurements taken at the beginning of data-taking every night. They **do not** perform this subtraction for softare-triggered events; they return the raw measured values. The measured values in the pedestal events are therefore offset from those in the on-sky events. The DAQ writes the measured baseline offsets into the `quabo_ph_baseline.json` files in the `pff` directories; these can be used to correct this difference.

---

## Theory of Operation

`capture_pedestal_events.py` sends regular [software-trigger commands](https://github.com/panoseti/panoseti/wiki/Quabo-packet-interface) to the four Quabo boards (each processing 256 pixels) at a fixed rate, listens for their responses, and optionally writes the data to a `.pcapng` and/or `.pff`file. The code has no external dependencies beyond the standard Python library, notably `asyncio`, and does not need any special privelages to run.

1. The script opens a UDP port, either with a fixed port assigned on the command line, or a randomly assigned one.
2. It starts a phase-locked polling loop with a fixed frequency of either *N Hz* or *1/N Hz* (with *N&le;1000*).
3. On each iteration a software trigger command is sent to all four Quabos concurrently.
4. The code waits a short time for the responses from the Quabos. If no writers are configured the responses are discarded.
5. **Optionally:** if writing in `.pcapng` format is configured: the response packet is transformed into a standard PANOSETI science packet and written to disk as a `.pcapng` file with a time-based rollover. See below for more details.
6. **Optionally:** if writing in `.pff` format is configured: the respone packets from the four Quabos are combined and written to a `.pff` file, with a size-based rollover. See below for more details.
7. A watchdog timer reports the number of pedestal events generated and the number of packets received lost.
8. The polling loop can be terminated by a ctrl-C or TERM signal.
9. **Optionally:** the script can listen for commands on a pre-defined UDP port (separate from the data port). It accepts a single command `STOP` in a UDP packet which terminates the polling loop. If configured, the script responds to this command with a UDP packet containing the bytes `STOPPING`.

### 1. PCAPNG file writer

PCAPNG is a [binary file format](https://pcapng.com/) desiged for writing network packets, and is used by by the packet-capture sofware *Wireshark*. A minimal implementation of a `.pcapng` file starts with two file-level headers, the `Section Header Block (SHB)` and the `Interface Description Block (IDB)`, followed by any number of paxket. Each packet must be prefixed by an `Enhanced Packet Block (EPB)` which contains the packet length and timestamp. The full packet is then written after the `EPB`.

To emulate the format of the normal onsky-trigger events that are written by the PANOSETI DAQ, the pedestal capture code can transform the responsees received from the Quabos into the science data-packet format, as describe below, encapsulate them in *fake* UDP/IP/Ethernet/EPB headers and write them to disk as a synthetic `.pcapng` file. **Note:** this does not involve running any packet capture code such as Wireshark, the Python code simply writes the headers ad data to the files itself. The code provides rollover of the `.pcapng` file at any desired time period (default 600 seconds).

The raw response packets from the quabos contain a 4-byte header and 512 bytes of pixel data (256 channels of 16-bit signed integers). The script repacks this data into a 528-byte PANOSETI Science Packet:

| Offset (Bytes) | Size | Field Name | Value / Description |
| :--- | :--- | :--- | :--- |
| `0` | 1B | `acq_mode` | `0x01` (Pulse Height) |
| `1` | 1B | `packet_ver` | `1` (16-bit signed PH) |
| `2` | 2B | `packet_no` | Lower 16-bits of pedestal PLL loop cycle counter |
| `4` | 2B | `boardloc` | Location ID: `(Module ID << 2) \| Quadrant ID` calculated from Quabi IP address |
| `6` | 4B | `TAI` | TAI seconds since epoch of *scheduled* pedestal event time from PLL loop (`UTC + tai_offset`) |
| `10` | 4B | `NANOSEC` | Sub-second time of *scheduled* pedestal event from PLL loop in nanoseconds |
| `14` | 2B | *Reserved* (or `Flags`?) | 0x0001 |
| `16` | 512B | `pixel_data` | 256 pixel values (16-bit unsigned values) |

**Note:** I propose that the *Reserved* field be considered as a *Flags* field in the future, allowing for future expansion without breaking compatibility. Here I propose that bit 0 (LSB) be used to indicate whether the payload contains a software triggered event.

This packet is enapusleted in a *UDP header* (8 bytes), an *IPv4 header* (20 bytes), an *EThernet II header* (14 bytes) and the *EPB header* (28 bytes) and *EPB footer$ (4 bytes) required by the PCAPNG format, for a total packet size of 570 bytes. Including the required padding to 4-byte boundaries, the total size of each packet in the `.pcapng` file is 604 bytes, or **2,416 bytes per event** (4 Quabos).


### 2. PFF file writer

PFF is a hybrid ascii/binary format described in the [PFF specification](https://github.com/panoseti/panoseti/wiki/Data-file-format). The measurements from the four Quabos are aligned and combined into a single image and written in binary format to the `.pff` file. This image is prefixed by a 491-byte JSON header and a single '*' to indicate the beginning of the binary data. The total **size of each event is 2,540 bytes**.

The JSON format and binary delimiter are illustrated below:

```json
{
   "quabo_0": { "pkt_num":          3, "pkt_tai":  762, "pkt_nsec": 500000000, "tv_sec": 1780926165, "tv_usec": 500000}, 
   "quabo_1": { "pkt_num":          3, "pkt_tai":  762, "pkt_nsec": 500000000, "tv_sec": 1780926165, "tv_usec": 500000}, 
   "quabo_2": { "pkt_num":          3, "pkt_tai":  762, "pkt_nsec": 500000000, "tv_sec": 1780926165, "tv_usec": 500000}, 
   "quabo_3": { "pkt_num":          3, "pkt_tai":  762, "pkt_nsec": 500000000, "tv_sec": 1780926165, "tv_usec": 500000}
}

*
```

Any missing packets will result in the values stored in the binary and JSON blocks being identically zero. Checking for `tv_sec==0` is a reliable way to identify such packets since this cannot occur in any other way.

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
| `--quabo-base-ip` | | *String* | *Site default* | Base IP address for quabo boards |
| `--module-id` | | *Int* | *Auto* | Module ID (calculated from IP if not set) |
| `--pcap-buffer` | | *Int* | *Dynamic* | Packets to buffer before write (Default: 60 or frequency) |
| `--compute-checksums` | | *Flag* | `False` | Enable IP/UDP checksum calculation |
| `--log-level` | | *String* | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `--log-file` | | *String* | `None` | Optional file to write log messages to |
| `--timeout` | | *Float* | `None` | UDP timeout in seconds (default: $0.5 \times \min(\text{Period}, 1.0)$) |
| `--quabos` | | *List* | `None` | Overrides site defaults with specific `host[:port]` |

---

## Command Port

If `--command-port` is set to a non-zero value, the script listens for UDP commands. 

- **STOP**: Sending the string `STOP` to the command port (no newline) will cause the script to signal a shutdown.
- **Response**: The script responds with `STOPPING` to the sender.
- **Termination**: Upon receiving `STOP`, the main run polling loop terminates immediately.
- **Grace Period**: The script waits for 2 seconds after the main loop has stopped before finally closing the command port and exiting. This allows for the `STOPPING` response to be resent if the original command is repeated (e.g., if the sender didn't receive the response due to UDP packet loss).

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
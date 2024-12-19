# OnlineHashCrack WPA/WPA2 Handshake Upload Plugin

This Pwnagotchi plugin automatically uploads WPA/WPA2 `.pcap` handshakes to [OnlineHashCrack.com](https://onlinehashcrack.com) using their new V2 API. It collects newly captured `.pcap` files, extracts hash lines in hashcat 22000 format using `hcxpcapngtool`, and sends them to the OnlineHashCrack API. The plugin also:

- Batches hashes in groups of up to 50 before uploading to comply with the API's limitations.
- Keeps track of which `.pcap` files and stations (ESSID/BSSID) have been uploaded, avoiding duplicates.
- Periodically checks if any tasks are cracked and updates a local potfile with recovered passwords.

## Features

- **Automated Upload:** Captured `.pcap` handshakes are automatically converted to `.22000` and uploaded to OnlineHashCrack.com.
- **Duplicate Prevention:** Once a `(ESSID, BSSID)` pair is uploaded, the plugin won’t submit it again.
- **Batch Uploading:** Handles batches of up to 50 hashes to comply with API constraints.
- **Potfile Integration:** Stores cracked passwords locally in a `.potfile` for easy reference.
- **No Dashboard Required:** Interacts purely through the OnlineHashCrack API (no manual dashboard downloads).

## Requirements

- **Pwnagotchi:** This plugin is designed to run on a [Pwnagotchi](https://pwnagotchi.ai) setup.
- **HCXTools:** You must have `hcxpcapngtool` installed for converting `.pcap` to `.22000` hash format.
- **OnlineHashCrack Account:** Obtain a free or paid API key from [OnlineHashCrack.com](https://onlinehashcrack.com).

## Installation

1. **Install HCXTools:**
   ```bash
   sudo apt-get update
   sudo apt-get install hcxtools
   ```
   Ensure `hcxpcapngtool` is available at `/usr/bin/hcxpcapngtool`.

2. **Plugin Setup:**
   - Place the plugin Python file (e.g., `onlinehashcrack.py`) into the `plugins/` directory of your Pwnagotchi.

3. **Configuration:**
   Edit your `config.toml` and add the plugin:
   ```toml
   main.plugins.onlinehashcrack.enabled = true
   main.plugins.onlinehashcrack.api_key = "sk_your_api_key_here"
   main.plugins.onlinehashcrack.receive_email = "yes"
   # Additional configuration as needed
   ```

## Usage

- When Pwnagotchi captures a new handshake `.pcap` file, this plugin:
  - Converts it to a `.22000` hash format.
  - Queues the hash for upload.
- On the next `on_internet_available` event:
  - All new `.pcap` files are processed.
  - New hashes are uploaded to OnlineHashCrack in batches of 50.
  - If successful, these `.pcap` files are marked as reported and their `(ESSID, BSSID)` is recorded.
- If any tasks are found cracked (`status = Found`), their passwords are written to `remote_cracking.potfile`.

## Potfile

Cracked passwords are appended to `remote_cracking.potfile` in the `handshakes` directory. The lines are formatted as:
```
/path/to/filename.pcap:password
```
This makes it easy to correlate recovered passwords with their original `.pcap` file.

## Troubleshooting

- **No Hashes Extracted:**  
  If the plugin logs `No hashes extracted`, ensure `hcxpcapngtool` is working correctly and that `.pcap` files contain valid handshakes.
- **API Errors:**  
  Verify your `api_key` is correct and that you agreed to terms (`agree_terms = "yes"` in code). Check your internet connection.

## Contributing

Pull requests and issues are welcome. If you find a bug or have an improvement, open an issue or submit a PR on GitHub.

## License

This plugin is released under the GPLv3 license. See the [LICENSE](LICENSE) file for more details.

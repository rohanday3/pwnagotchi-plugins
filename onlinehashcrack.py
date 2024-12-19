import os
import logging
import requests
from datetime import datetime
from threading import Lock
from pwnagotchi.utils import StatusFile
import pwnagotchi.plugins as plugins
from json.decoder import JSONDecodeError

class OnlineHashCrack(plugins.Plugin):
    __author__ = 'Rohan Dayaram'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Uploads WPA/WPA2 handshakes to OnlineHashCrack.com using the new API (V2), no dashboard.'

    def __init__(self):
        self.ready = False
        self.lock = Lock()
        try:
            self.report = StatusFile('/root/handshakes/.ohc_uploads', data_format='json')
        except JSONDecodeError:
            os.remove('/root/.ohc_newapi_uploads')
            self.report = StatusFile('/root/handshakes/.ohc_uploads', data_format='json')
        self.skip = list()
        self.potfile = '/root/handshakes/remote_cracking.potfile'

    def on_loaded(self):
        """
        Called when the plugin is loaded.
        """
        required_fields = ['api_key']
        missing = [field for field in required_fields if field not in self.options or not self.options[field]]
        if missing:
            logging.error(f"OHC NewAPI: Missing required config fields: {missing}")
            return

        if 'receive_email' not in self.options:
            self.options['receive_email'] = 'yes'  # default

        self.ready = True
        logging.info("OHC NewAPI: Plugin loaded and ready.")

    def on_internet_available(self, agent):
        if not self.ready or self.lock.locked():
            return

        with self.lock:
            display = agent.view()
            config = agent.config()
            reported = self.report.data_field_or('reported', default=[])
            processed_stations = self.report.data_field_or('processed_stations', default=[])
            handshake_dir = config['bettercap']['handshakes']

            # Find .pcap files
            handshake_filenames = os.listdir(handshake_dir)
            handshake_paths = [os.path.join(handshake_dir, filename)
                                for filename in handshake_filenames if filename.endswith('.pcap')]

            # Filter out already reported and skipped .pcap files
            handshake_new = set(handshake_paths) - set(reported) - set(self.skip)

            if handshake_new:
                logging.info(f"OHC NewAPI: Internet detected. Processing {len(handshake_new)} new PCAP handshakes.")

                all_hashes = []
                successfully_extracted = []
                essid_bssid_map = {}  # Map from pcap_path to (essid, bssid)

                for idx, pcap_path in enumerate(handshake_new):
                    display.on_uploading(f"Extracting hashes ({idx + 1}/{len(handshake_new)})")
                    hashes = self._extract_hashes_from_handshake(pcap_path)
                    if hashes:
                        # Each pcap usually has one hash line
                        # Extract ESSID and BSSID from the first hash line to check for duplicates
                        essid, bssid = self._extract_essid_bssid_from_hash(hashes[0])
                        if (essid, bssid) in processed_stations:
                            logging.debug(f"OHC NewAPI: Station {essid}/{bssid} already processed, skipping {pcap_path}.")
                            self.skip.append(pcap_path)
                            continue

                        all_hashes.extend(hashes)
                        successfully_extracted.append(pcap_path)
                        essid_bssid_map[pcap_path] = (essid, bssid)
                    else:
                        logging.debug(f"OHC NewAPI: No hashes extracted from {pcap_path}, skipping.")
                        self.skip.append(pcap_path)

                # Now we have all_hashes collected. Upload them in batches of 50
                if all_hashes:
                    batches = [all_hashes[i:i+50] for i in range(0, len(all_hashes), 50)]
                    upload_success = True
                    for batch_idx, batch in enumerate(batches):
                        display.on_uploading(f"onlinehashcrack.com ({(batch_idx+1)*50}/{len(all_hashes)})")
                        if not self._add_tasks(batch):
                            upload_success = False
                            break

                    if upload_success:
                        # If uploaded successfully, mark all successfully extracted pcaps as reported
                        for pcap_path in successfully_extracted:
                            reported.append(pcap_path)
                            essid, bssid = essid_bssid_map[pcap_path]
                            processed_stations.append((essid, bssid))
                        self.report.update(data={'reported': reported, 'processed_stations': processed_stations})
                        logging.debug("OHC NewAPI: Successfully reported all new handshakes.")
                    else:
                        # If upload failed, skip all these pcaps
                        for pcap_path in successfully_extracted:
                            self.skip.append(pcap_path)
                        logging.debug("OHC NewAPI: Failed to upload tasks, added to skip list.")
                else:
                    logging.debug("OHC NewAPI: No hashes were extracted from the new pcaps. Nothing to upload.")

                display.on_normal()
            else:
                logging.debug("OHC NewAPI: No new PCAP files to process.")

            # Additionally, check if any tasks are found/cracked and update potfile if needed
            tasks = self._list_tasks()
            if tasks is not None:
                found_tasks = [t for t in tasks if t.get('status') == 'Found']
                if found_tasks:
                    logging.info(f"OHC NewAPI: Found {len(found_tasks)} cracked tasks, updating potfile.")
                    self._update_potfile_with_found_tasks(found_tasks)
                else:
                    logging.info("OHC NewAPI: No cracked tasks found this time.")


    def _extract_essid_bssid_from_hash(self, hash_line):
        """
        Extract ESSID and BSSID from a single hash line (WPA*02*...).
        Similar to _extract_essid_from_task and _extract_bssid_from_task but for a raw hash line.
        """
        parts = hash_line.strip().split('*')
        essid = 'unknown_ESSID'
        bssid = '00:00:00:00:00:00'

        # ESSID is at index 5 (0-based)
        if len(parts) > 5:
            essid_hex = parts[5]
            try:
                essid = bytes.fromhex(essid_hex).decode('utf-8', errors='replace')
            except:
                essid = 'unknown_ESSID'

        # BSSID (AP MAC) is at index 3
        if len(parts) > 3:
            apmac = parts[3]
            if len(apmac) == 12:
                bssid = ':'.join(apmac[i:i+2] for i in range(0, 12, 2))

        return essid, bssid



    def _list_tasks(self, timeout=30):
        """
        Lists current tasks from the API.
        """
        payload = {
            'api_key': self.options['api_key'],
            'agree_terms': "yes",
            'action': 'list_tasks'
        }

        try:
            result = requests.post('https://api.onlinehashcrack.com/v2',
                                   json=payload,
                                   timeout=timeout)
            result.raise_for_status()
            data = result.json()
            if data.get('success', False):
                logging.info(f"OHC NewAPI: Retrieved {len(data.get('tasks', []))} tasks.")
                return data.get('tasks', [])
            else:
                logging.error("OHC NewAPI: Failed to list tasks.")
                return None
        except requests.exceptions.RequestException as e:
            logging.debug(f"OHC NewAPI: Exception while listing tasks -> {e}")
            return None

    def _update_potfile_with_found_tasks(self, found_tasks):
        """
        Update the potfile with found passwords.
        Assuming found tasks come with a 'password' field in the API response.
        If the API does not supply 'password' directly, adjust this logic according to the actual API.
        """
        ap_map = self.report.data_field_or('ap_map', default={})
        new_entries = []

        for task in found_tasks:
            essid = self._extract_essid_from_task(task)
            bssid = self._extract_bssid_from_task(task)
            password = task.get('password', '')  # Assuming password field
            if password and essid and bssid:
                key = f"{essid}_{bssid}"
                if key in ap_map:
                    filename = ap_map[key]
                    line = f"{filename}:{password}\n"
                    new_entries.append(line)

        if not new_entries:
            logging.debug("OHC NewAPI: No new passwords to update in potfile.")
            return

        existing = set()
        if os.path.exists(self.potfile):
            with open(self.potfile, 'r') as pf:
                existing = set(pf.readlines())

        combined = existing.union(new_entries)
        with open(self.potfile, 'w') as pf:
            pf.writelines(sorted(combined))

        logging.info("OHC NewAPI: Potfile updated with cracked passwords.")

    def _add_tasks(self, hashes, timeout=60):
        """
        Adds a batch of up to 50 new tasks to the service using the new API.
        """
        clean_hashes = [h.strip() for h in hashes if h.strip()]
        if not clean_hashes:
            return True  # No hashes to add is considered success

        payload = {
            'api_key': self.options['api_key'],
            'agree_terms': "yes",
            'action': 'add_tasks',
            'algo_mode': 22000,  # WPA/WPA2 PMKID/handshake mode
            'hashes': clean_hashes,
            'receive_email': self.options['receive_email']
        }

        try:
            result = requests.post('https://api.onlinehashcrack.com/v2',
                                   json=payload,
                                   timeout=timeout)
            result.raise_for_status()
            data = result.json()
            logging.info(f"OHC NewAPI: Add tasks response: {data}")
            return True
        except requests.exceptions.RequestException as e:
            logging.debug(f"OHC NewAPI: Exception while adding tasks -> {e}")
            return False

    def _extract_hashes_from_handshake(self, pcap_path):
        """
        Extract hashes from the given handshake PCAP file using hcxpcapngtool.
        """
        hashes = []
        hcxpcapngtool = '/usr/bin/hcxpcapngtool'
        hccapx_path = pcap_path.replace('.pcap', '.22000')
        hcxpcapngtool_cmd = f"{hcxpcapngtool} -o {hccapx_path} {pcap_path}"
        os.popen(hcxpcapngtool_cmd).read()
        if os.path.exists(hccapx_path) and os.path.getsize(hccapx_path) > 0:
            logging.debug(f"OHC NewAPI: Extracted hashes from {pcap_path}")
            with open(hccapx_path, 'r') as hccapx_file:
                hashes = hccapx_file.readlines()
        else:
            logging.debug(f"OHC NewAPI: Failed to extract hashes from {pcap_path}")
            if os.path.exists(hccapx_path):
                os.remove(hccapx_path)
        return hashes

    def _extract_essid_from_task(self, task):
        """
        Extract ESSID from a task entry.
        The actual method depends on how ESSID is returned by OHC in 'list_tasks'.
        If the hash line or a field in the task contains the ESSID, parse it out.
        This is a placeholder logic.
        """
        # Example: If task['hash'] is a standard WPA* line containing ESSID.
        # WPA*02*...*ESSID*...
        # You'll need to parse the hash line or another field that OHC returns.
        # For demonstration, assume the hash line has ESSID after some delimiter.
        hash_line = task.get('hash', '')
        # This is very dependent on the hash format. 
        # Typically 22000 format is: WPA*02*PMKID*APmac*CLmac*ESSID*... 
        # We can split by '*'
        parts = hash_line.split('*')
        if len(parts) > 5:
            essid_hex = parts[5]
            # ESSID is hex, decode it:
            try:
                essid = bytes.fromhex(essid_hex).decode('utf-8', errors='replace')
                return essid
            except:
                return 'unknown_ESSID'
        return 'unknown_ESSID'

    def _extract_bssid_from_task(self, task):
        """
        Extract BSSID from a task entry.
        Similar logic to _extract_essid_from_task.
        """
        hash_line = task.get('hash', '')
        parts = hash_line.split('*')
        # For 22000: parts[3] is AP MAC
        if len(parts) > 3:
            # AP MAC is in hex, we might need to format it
            # If APmac = a25322ba457a then BSSID = a2:53:22:ba:45:7a
            apmac = parts[3]
            if len(apmac) == 12:
                bssid = ':'.join(apmac[i:i+2] for i in range(0,12,2))
                return bssid
        return '00:00:00:00:00:00'

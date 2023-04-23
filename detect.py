"""
Title: Malware Detector for Volatility
Author: Hamza Ijaz
Student Number: 001098354
Email: hi5456m@gre.ac.uk
Date created: 14/04/2023

This is a script for Volatility 3.0 that automates the malware detection process
using various plugins, the online malware signature repository VirusTotal and an
extensive list of YARA rules.
"""

import argparse
import datetime
import hashlib
import glob
import time
import logging
import os
import requests
import shutil
import subprocess


class UpdateYARA:
    """
    Downloads the YARA rules repository from https://github.com/Yara-Rules/rules.git
    and saves it as "malware_rules.yar". If repository exists already, it will be updated
    """

    def __init__(self, rules_repository: str = "https://github.com/Yara-Rules/rules.git"):
        self.rules_repository = rules_repository

    def clone_rules_repository(self):
        """
        Clone the repository in path using git
        """


        if os.path.exists("./rules"):
            # Recursively delete the directory "./rules" and all of its contents
            shutil.rmtree("./rules", onerror=self.remove_readonly)
        # Use git to clone YARA rules in current directory
        os.system(f"git clone {self.rules_repository}")

    def list_rules(self):
        """
        Adds each rule found in the repository
        :return: list of all rule files
        """

        # Initialise empty list to hold all rules
        all_files = []
        # Starting from "./rules/malware", go through the directory tree
        for root, _, filenames in os.walk("./rules/malware"):
            # Print a message indicating which directory is being processed
            print(f"Processing {root}")
            filenames.sort()
            # Loop through file in current directory
            for file_name in filenames:
                rule_filename, rule_file_extension = os.path.splitext(file_name)
                # Check file extension, only accepts ".yar" or ".yara"
                if rule_file_extension in [".yar", ".yara"]:
                    # Add the full path of the file to the list of all files
                    all_files.append(os.path.join(root, file_name))

        return all_files

    @staticmethod
    def remove_readonly(func, path, _):
        """
        Allows to add files to current path.
        """

        # Change directory's permission to 0o777, which sets read, write, and execute permissions.
        os.chmod(path, 0o777)
        func(path)

    @staticmethod
    def remove_incompatible(files):
        """
        Filters out incompatible rules
        :return: list of filtered files
        """

        # List of incompatible YARA imports
        incompatible_imports = ["import \"math\"", "import \"cuckoo\"", "import \"hash\"", "imphash"]
        # Initiate list that will hold filtered files
        filtered = []
        # Loop through each YARA file in the input list
        for yara_file in files:
            # Open YARA file
            with open(yara_file, 'r') as fd:
                yara_in_file = fd.read() # Convert contents into string
                # Check if incompatible imports are in the YARA file
                if not any(imp in yara_in_file for imp in incompatible_imports):
                    filtered.append(yara_file)

        return filtered

    @staticmethod
    def fix_duplicates(files):
        """
        If the repository has already been downloaded, this avoids duplicates
        :return: filtered list of YARA rules
        """

        # Initiate empty list to hold YARA rules
        filtered = []
        # Initialise a boolean flag to check whether current YARA rule has name "is__elf"
        first_elf = True
        # Initialise a boolean flag to check whether current YARA rule should be deleted because duplicate
        to_delete = False
        # Loop through each YARA file in the input list
        for yara_file in files:
            # Show which YARA rule is being processed
            print(f"Processing {yara_file}")
            # Open YARA file
            with open(yara_file, 'r') as fd:
                # Read line-by-line the content of YARA file
                yara_in_file = fd.readlines()
                # Loop through lines in the YARA file
                for line in yara_in_file:
                    # Check if current line starts with "is__elf"
                    if line.strip() == "private rule is__elf {":
                        # If this is the first "is__elf" encountered, set flag to False
                        if first_elf:
                            first_elf = False
                        # Otherwise, set to True, which indicates it is a duplicate
                        else:
                            to_delete = True
                    # If not duplicate, add to filtered
                    if not to_delete:
                        filtered.append(line)
                    # Check if current line the end of an "is__elf" rule
                    if (not first_elf) and line.strip() == "}":
                        # If it is the end of a duplicate, set flag back to False to allow filtered rules to be added
                        to_delete = False
                filtered.append("\n")

        return filtered

    @staticmethod
    def merge_rules(all_rules):
        """
        Merges existing 'malware_rules.yar' file with the new one when updating
        """

        with open("malware_rules.yar", 'w') as fd:
            fd.write(''.join(all_rules))

    def process_rules(self):
        """
        Merges existing 'malware_rules.yar' file with the new one when updating
        """

        # Clone repository, get files, remove incompatibles and duplicates and create new or merge to existing file
        self.clone_rules_repository()
        all_files = self.list_rules()
        filtered_1 = self.remove_incompatible(all_files)
        filtered_2 = self.fix_duplicates(filtered_1)
        self.merge_rules(filtered_2)


class DetectMalware:
    """
    A class for detecting malware in a memory image using the Volatility Framework
    """

    def __init__(self, memory_image):
        """
        Initializes a DetectMalware object.
        :param memory_image: The path to the memory image file
        """

        # Set the VirusTotal API key, memory image path, output and report directories
        self.api_key = "24610375250fa23e5dd6c6d72cc4b405c7f6384cd3cf89be0960a94929b3099e"
        self.memory_image = memory_image
        self.output_directory = "Process Dumps"
        self.report_directory = "Detector Scan Reports"
        # Set logger
        self.logger = self._setup_logger(self.memory_image)

    def _setup_logger(self, memory_image):
        """
        Sets up a logger object to log the detection results.
        :return: The logger object
        """

        # Create directory for report files if it doesn't exist
        os.makedirs(self.report_directory, exist_ok=True)

        # Generate log file name
        basename = os.path.basename(memory_image)
        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = basename + "_" + current_time + ".txt"
        dir_filename = f"{self.report_directory}/{filename}"

        # Set up logger object
        logger = logging.getLogger("detection_logger")
        logger.setLevel(logging.INFO)

        # Set up file handler and stream handler for logging
        file_handler = logging.FileHandler(dir_filename)
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

        # Return logger object
        return logger

    def md5_calculate(self, file_path):
        """
        Calculates the MD5 hash value of a file.
        :param file_path: path to the dump of the process
        :return: the MD5 hash value of the dump file
        """

        try:
            hasher = hashlib.md5()
            # Open the file in binary mode
            with open(file_path, "rb") as f:
                # Read contents into a buffer
                buf = f.read()
                # Update hash object with buffer's content
                hasher.update(buf)
            return hasher.hexdigest()
        # Handle OSError that happens if Antivirus removes the dump before it can be checked because contains malware
        # Note: code is inside memory dump, so it is not active and is harmless unless properly extracted
        except OSError:
            print(f"OS Antivirus has detected a malware in this process dump and deleted the file.")
            print(f"Further investigate to find out more.")

    def run_yara(self):
        """
        Scans all processes using the YARA rules set in file 'malware_rules.yar'.
        """

        self.line()
        self.logger.info("Checking malware signatures in all processes using YARA rules...\n")
        # Start a subprocess to run the YARA scan using the VadYaraScan plugin
        with subprocess.Popen(
                ["python", "vol.py", "-f", self.memory_image, "windows.vadyarascan.VadYaraScan", "--yara-file",
                 "malware_rules.yar"], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as p:
            # Iterate over the output line by line and display it in the console and log it
            for line in p.stdout:
                self.logger.info(line.strip())

    def run_malfind(self, memory_image):
        """
        Run the Malfind plugin to search for possible injected code.
        """

        self.line()
        self.logger.info("Running the Malfind plugin...\n")
        # Construct the command to run Malfind
        cmd = f"python vol.py -f {memory_image} windows.malfind.Malfind"
        # Run Malfind using a subprocess
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # Create empty string to hold output
        raw_data = ""

        for line in process.stdout:
            line = line.decode().rstrip()
            print(line)
            raw_data += line + "\n"

        return_code = process.wait()

        print(f"\nReturn code: {return_code}")
        self.logger.info("Here are malicious processes identified using the plugin Malfind.")
        self.logger.info("To further investigate, check the memory regions between 'Start VPN' and 'End VPN'\n")

        lines = raw_data.strip().split('\n')
        # Initialise empty list to hold formatted data
        formatted_data = []

        # Loop through each line of variable raw_data
        for line in lines:
            if 'Vad' in line:
                # Split the line into its component parts
                parts = line.split()
                pid = parts[0]
                process = parts[1]
                start_vpn = parts[2]
                end_vpn = parts[3]
                # Add formatted data to list
                formatted_data.append((pid, process, start_vpn, end_vpn))

        # Add a header for the output
        self.logger.info("PID\tProcess\t\tStart VPN\tEnd VPN")
        self.logger.info("-" * 46)

        # Log only entries in formatted data
        for entry in formatted_data:
            self.logger.info(f"{entry[0]}\t{entry[1]}\t{entry[2]}\t{entry[3]}")

    def run_pslist(self, memory_image):
        """
        Run the Volatility 'pslist' plugin to display all processes.
        :return: output of the subprocess decoded into 'utf-8'
        """

        print(f"\nStarting memory image analysis for {memory_image}...\n")
        # Construct command to run PsList plugin
        cmd = ["python", "vol.py", "-f", self.memory_image, "windows.pslist.PsList"]
        self.logger.info("Processes running at the time of acquisition:")
        # Run PsList plugin using subprocess
        cmd_output = subprocess.check_output(cmd).decode("utf-8)")
        self.logger.info(cmd_output)

        return cmd_output

    def run_detector(self, pslist_output):
        """
        Analyses the memory image using Volatility framework to identify malicious processes
        """

        self.line()
        self.logger.info("Scanning each process using the VirusTotal database...")

        # Extract the process list from the output of 'pslist' plugin
        lines = pslist_output.split("\n")
        header_line = -1
        for i, line in enumerate(lines):
            # Find line containing the headers of the list
            if "PID" in line and "PPID" in line:
                header_line = i
                break

        if header_line == -1:
            print("Could not find the header line. Exiting.")
            exit()

        # Extract process information from output
        lines = lines[header_line + 1:]

        # Iteration to check each process against the VirusTotal database
        for line in lines:
            if not line.strip():
                continue
            columns = line.split()

            if len(columns) < 1 or not columns[0].isdigit():
                continue

            pid = int(columns[0])

            # Dump the memory of the process with given PID
            print(f"\nDumping process with PID {pid}")
            subprocess.run(["python", "vol.py", "-f", self.memory_image, "-o", self.output_directory,
                            "windows.pslist.PsList", "--pid", str(pid), "--dump"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Get path of the generated dump file
            dump_file_paths = glob.glob(os.path.join(self.output_directory, f"pid.{pid}.*.dmp"))

            if dump_file_paths:
                dump_file_path = dump_file_paths[0]
                # Calculate the MD5 hash of the dumped memory
                md5_hash_value = self.md5_calculate(dump_file_path)
                self.logger.info(f"MD5 hash of process {pid}: {md5_hash_value}")
                # Delete the generated dump file after calculating MD5 as no longer needed
                os.remove(dump_file_path)
                # Check the MD5 hash against the VirusTotal database
                self.check_virus_total(md5_hash_value, f'Process with PID {pid}')
            else:
                print(f"Failed to generate dump for process with PID {pid}")

    def check_virus_total(self, md5_hash, process_pid):
        """
        Checks VirusTotal for the MD5 hash value of a file
        :param md5_hash: the MD5 hash value of the file
        :param process_pid: the PID of the process
        """

        # Set up the API endpoint and request headers
        url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
        headers = {
            'x-apikey': self.api_key
        }

        # Send a GET request to VirusTotal
        response = requests.get(url, headers=headers)

        # Parse JSON response if response code is 200
        if response.status_code == 200:
            json_response = response.json()
            scan_results = json_response['data']['attributes']['last_analysis_stats']

            # Log findings
            if scan_results['malicious'] > 0:
                self.logger.warning(f"{process_pid} is likely MALICIOUS because {scan_results['malicious']} out of "
                                    f"{scan_results['malicious'] + scan_results['undetected']} scanners matched in "
                                    f"the VirusTotal database:")
                self.logger.info(f"  Malicious: {scan_results['malicious']}")
                self.logger.info(f"  Suspicious: {scan_results['suspicious']}")
                self.logger.info(f"  Undetected: {scan_results['undetected']}\n")
            else:
                self.logger.info(f"{process_pid} is not detected as malicious.")
        # If response code is 404 it means it was not found in the VirusTotal database
        elif response.status_code == 404:
            self.logger.info(f"{process_pid} was not found in the VirusTotal database.")
        # Show error message if any other result status code is given
        else:
            self.logger.error(f"An error occurred: {response.status_code}")

    def line(self):
        """ Simple code to add separator lines for logging purposes"""

        self.logger.info("\n")
        self.logger.info("-" * 130)
        self.logger.info("\n")

    def main(self, memory_image):
        """
        Run all functions in order to construct the script properly.
        """

        # Create output directory for storing the results of the analysis
        os.makedirs(self.output_directory, exist_ok=True)

        # Record output of PsList plugin into variable
        pslist_output = self.run_pslist(memory_image)

        t = time.time()

        # Check if file "malware_rules.yar" exists
        try:
            with open("malware_rules.yar", "r"):
                self.run_yara()
        # If not found, run class UpdateYARA to download
        except FileNotFoundError:
            print("\nThe YARA rules repository was not found. Downloading...")
            obj = UpdateYARA()
            obj.process_rules()
            self.run_check()

        self.logger.info(f"\nTime taken for YARA rules checks: {(time.time() - t):.2f} seconds" )

        # Run Malfind
        self.run_malfind(memory_image)

        # Run the MD5 checks using memory dump of each process
        self.run_detector(pslist_output)

if __name__ == "__main__":
    start_time = time.time()

    #Set parser
    parser = argparse.ArgumentParser(description="Malware Detector for Volatility")
    # Set argument -u
    parser.add_argument("-u", "--update", action="store_true",
                        help="Upgrade current YARA rules repository")
    # Set argument -f
    parser.add_argument('-f', '--file', help='Path/directory to the memory image')
    # Parse the command-line arguments
    args = parser.parse_args()

    # Check which argument has been given and run the right class accordingly
    if args.update:
        yara_rules = UpdateYARA()
        yara_rules.process_rules()
        end_time = time.time()
        total_time = end_time - start_time
        print(f"\nTotal time taken to update YARA rules: {total_time:.2f} seconds")
    elif args.file:
        analysis = DetectMalware(args.file)
        analysis.main(args.file)
        end_time = time.time()
        total_time = end_time - start_time
        print(f"\nTotal time taken for analysis: {total_time:.2f} seconds")
    else:
        print("Run command <python detect.py -h> for more information.")

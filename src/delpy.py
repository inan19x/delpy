#!/usr/bin/env python3

import configparser
import os
import re
import socket
import sys
import time
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class Delpy:
    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        abs_config = os.path.abspath(config_file)
        if not os.path.exists(abs_config):
            print(f"Error: Configuration file not found at {abs_config}", file=sys.stderr)
            sys.exit(1)
            
        self.config.read(abs_config)

        try:
            self.watch_directory = os.path.abspath(self.config["monitor"]["watch_directory"])
            self.pattern_file = os.path.abspath(self.config["signature"]["pattern_file"])
            self.log_file = os.path.abspath(self.config["logging"]["log_file"])
            self.encoding = self.config["encoding"]["encoding"]
            self.max_file_size = int(self.config["maxfilesize"]["max_file_size_mb"]) * 1024 * 1024
        except KeyError as e:
            print(f"Error: Missing configuration option in conf: {e}", file=sys.stderr)
            sys.exit(1)

        self.hostname = socket.gethostname()
        self.source_ip = self.get_source_ip()
        self.signatures = []
        self.load_signatures()

    def get_source_ip(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except OSError:
            return "unknown"

    def load_signatures(self):
        if not os.path.exists(self.pattern_file):
            print(f"Error: Signature file not found at {self.pattern_file}", file=sys.stderr)
            return
            
        try:
            with open(self.pattern_file, "r", encoding=self.encoding) as file:
                for line_number, line in enumerate(file, start=1):
                    raw_line = line.strip()
                    if not raw_line or raw_line.startswith("#"):
                        continue
                    
                    if raw_line.lower().startswith("name,regex,sensitivity"):
                        continue

                    first_comma = raw_line.find(",")
                    last_comma = raw_line.rfind(",")

                    if first_comma == -1 or last_comma == -1 or first_comma == last_comma:
                        print(f"Warning: Invalid structure formatting at line {line_number}", file=sys.stderr)
                        continue

                    name = raw_line[:first_comma].strip()
                    pattern = raw_line[first_comma + 1:last_comma].strip()
                    sensitivity = raw_line[last_comma + 1:].strip().upper()

                    try:
                        regex = re.compile(pattern)
                    except re.error as error:
                        print(f"Error compiling regex at line {line_number}: {error}", file=sys.stderr)
                        continue

                    self.signatures.append({
                        "name": name,
                        "regex": regex,
                        "sensitivity": sensitivity,
                    })
            
            print(f"Successfully loaded {len(self.signatures)} signature(s) from {self.pattern_file}")
            
        except OSError as e:
            print(f"Critical: Error reading signature file: {e}", file=sys.stderr)

    def _wait_for_file_stability(self, path, retries=3, delay=0.05):
        if not os.path.exists(path):
            return False
            
        try:
            with open(path, "r", encoding=self.encoding, errors="ignore") as f:
                f.read(1)
            return True
        except OSError:
            pass

        last_size = -1
        for _ in range(retries):
            try:
                current_size = os.path.getsize(path)
                if current_size == last_size and current_size > 0:
                    return True
                last_size = current_size
            except OSError:
                pass
            time.sleep(delay)
            
        return os.path.exists(path)

    def scan_file(self, path):
        if os.path.abspath(path) == os.path.abspath(self.log_file):
            return

        if not os.path.isfile(path):
            return

        if not self._wait_for_file_stability(path):
            return

        try:
            file_size = os.path.getsize(path)
            if file_size > self.max_file_size or file_size == 0:
                return

            matched_signatures = set()
            chunk_size = 64 * 1024
            
            with open(path, "r", encoding=self.encoding, errors="ignore") as file:
                overlap = ""
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    
                    content_to_scan = overlap + chunk
                    
                    for sig in self.signatures:
                        if sig["name"] in matched_signatures:
                            continue
                        if sig["regex"].search(content_to_scan):
                            self.alert(sig["name"], sig["sensitivity"], os.path.basename(path))
                            matched_signatures.add(sig["name"])
                    
                    overlap = chunk[-500:] if len(chunk) > 500 else chunk
                    
        except Exception as e:
            print(f"Error scanning file {path}: {e}", file=sys.stderr)

    def alert(self, signature, sensitivity, filename):
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = (
            f"{timestamp} ALERT delpy: "
            f"signature={signature} "
            f"sensitivity={sensitivity} "
            f"host={self.hostname} "
            f"srcip={self.source_ip} "
            f"file={filename}"
        )
        print(message)

        log_directory = os.path.dirname(self.log_file)
        if log_directory:
            os.makedirs(log_directory, exist_ok=True)

        try:
            with open(self.log_file, "a", encoding=self.encoding) as log:
                log.write(message + "\n")
        except OSError as e:
            print(f"Logging Failure: {e}", file=sys.stderr)



class DelpyEventHandler(FileSystemEventHandler):
    def __init__(self, delpy):
        super().__init__()
        self.delpy = delpy

    def on_created(self, event):
        if event.is_directory:
            return
        self.delpy.scan_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self.delpy.scan_file(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            if os.path.isdir(event.dest_path):
                for root, _, files in os.walk(event.dest_path):
                    for file in files:
                        self.delpy.scan_file(os.path.join(root, file))
            return
        self.delpy.scan_file(event.dest_path)


def main():
    config_file = "config/delpy.conf"
    if len(sys.argv) > 1:
        config_file = sys.argv[1]

    delpy = Delpy(config_file)

    if not os.path.isdir(delpy.watch_directory):
        print(f"Watch directory does not exist: {delpy.watch_directory}", file=sys.stderr)
        sys.exit(1)

    event_handler = DelpyEventHandler(delpy)
    observer = Observer()
    observer.schedule(event_handler, delpy.watch_directory, recursive=True)
    observer.start()

    print(f"[*] Delpy engine monitoring directory: {delpy.watch_directory}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()


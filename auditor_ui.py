import os
import subprocess
import sys
from tabulate import tabulate

class ChuMantarUI:
    def __init__(self):
        self.red = "\033[0;31m"
        self.green = "\033[0;32m"
        self.blue = "\033[0;34m"
        self.reset = "\033[0m"

    def banner(self):
        print(f"{self.blue}")
        print("=" * 60)
        print("         CHU-MANTAR-CHU: PROFESSIONAL WIFI AUDITOR")
        print("=" * 60)
        print(f"{self.reset}")

    def log(self, message, level="INFO"):
        colors = {"INFO": self.blue, "SUCCESS": self.green, "ERROR": self.red}
        print(f"{colors.get(level, self.reset)}[{level}]{self.reset} {message}")

    def run_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.log(f"Command failed: {e}", "ERROR")
            return None

    def main_menu(self):
        self.banner()
        self.log("Starting security audit initialization...")
        
        if os.geteuid() != 0:
            self.log("Please run with sudo.", "ERROR")
            sys.exit(1)

        # In a real scenario, this would call the bash script or implement the logic here
        self.log("System check passed. Ready to audit.", "SUCCESS")
        print("\n1. Start Full Audit")
        print("2. Check Dependencies")
        print("3. View Last Report")
        print("4. Exit")
        
        choice = input("\nSelect an option: ")
        if choice == "1":
            subprocess.run(["bash", "/home/ubuntu/chu-mantar-chu.sh"])
        else:
            print("Exiting...")

if __name__ == "__main__":
    ui = ChuMantarUI()
    ui.main_menu()

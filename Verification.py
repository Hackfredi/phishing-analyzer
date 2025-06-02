# menu.py
import os
import subprocess
import sys
from pathlib import Path

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_menu():
    clear_screen()
    print("""
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    """)
    print("1. Check for Phishing (Run body.py)")
    print("2. Connect to IMAP (Run imap_setup.py)")
    print("3. Exit")
    choice = input("\nEnter your choice (1-3): ")
    return choice

def run_script(script_name):
    """Generic function to run a Python script in the same directory"""
    try:
        script_path = Path(__file__).parent / script_name
        if not script_path.exists():
            print(f"Error: Cannot find {script_name} in {script_path.parent}")
            return False
        
        # Use the same Python executable that's running this script
        python_exe = sys.executable
        subprocess.run([python_exe, str(script_path)], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running {script_name}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

def run_check():
    clear_screen()
    print("Running phishing check (body.py)...")
    run_script("Checks/body.py")
    input("\nPress Enter to return to menu...")

def run_connect():
    clear_screen()
    print("Connecting to IMAP (imap_setup.py)...")
    run_script("Checks/imap_setup.py")
    input("\nPress Enter to return to menu...")

def main():
    while True:
        choice = show_menu()
        if choice == "1":
            run_check()
        elif choice == "2":
            run_connect()
        elif choice == "3":
            print("Exiting program...")
            break
        else:
            print("Invalid choice, please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
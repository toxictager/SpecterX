# main.py
import os
from core import scanner, osint, brute, web, post_exploit
from utils import reporter

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("""
   ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗  ╗██╗  ██╗  
   ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗  ╚██╗██╔╝  
   ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝   ╚███╔╝ 
   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔═══╝    ██╔██╗
   ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║       ██╔╝ ██╗ 
   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝       ╚═╝  ╚═╝
            by toxictager | Recon & OSINT Toolkit
    """)

def main():
    while True:
        clear()
        print_banner()
        print("""
[1] Technical Recon
[2] OSINT Toolkit
[3] Brute-Force
[4] Web Arsenal
[5] Post-Exploitation
[6] Exit
        """)
        choice = input("Select an option: ").strip()

        if choice == '1':
            scanner.run()
        elif choice == '2':
            osint.run()
        elif choice == '3':
            brute.run()
        elif choice == '4':
            web.run()
        elif choice == '5':
            post_exploit.run()
        elif choice == '6':
            print("Goodbye.")
            break
        else:
            input("Invalid choice. Press Enter to try again.")

if __name__ == "__main__":
    main()

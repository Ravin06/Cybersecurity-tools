#Port Scanner tool
import nmap

scanner = nmap.PortScanner()
ip = input("Enter the IP address you want to scan: ")
#-sV: Probe open ports to determine service/version info
#-sC: equivalent to --script=default
while True:
    options = input("Enter the options you want to use (Enter NA for default which is -sV -sC): ")
    if options == "NA":
        options = "-sV -sC"
        break
    else:
        options = options.split()
        for option in options:
            if option not in ["-sS", "-sT", "-sU", "-sA", "-sW", "-sM", "-sP", "-sn", "-sI", "-p", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "--min-rate", "-oN", "-oX", "-oG", "-oA", "-sV", "-sC", "-O", "--osscan-guess", "--script", "-A", "-p-", "-Pn", "-R", "--traceroute"]:
                print(f"Invalid option {option}. Please enter valid options")
                break
        else:
            options = " ".join(options)
            break
        break

#Scan the IP address with the options
print(f"Scanning IP address {ip} with options {options}")
scanner.scan(ip, arguments=options)

for host in scanner.all_hosts():
    #Print the hostname, state, protocol, port, state and name
    print(f"Host: {host} ({scanner[host].hostname()})")
    print(f"State: {scanner[host].state()}")
    for proto in scanner[host].all_protocols():
        print(f"Protocol: {proto}")
        ports = scanner[host][proto].keys()
        for port in ports:
            print(f"Port: {port}\tState: {scanner[host][proto][port]['state']}\tName: {scanner[host][proto][port]['name']}")
          

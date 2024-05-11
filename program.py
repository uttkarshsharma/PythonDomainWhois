import whois
import socket

def get_domain_info(domain):
    try:
        # Perform WHOIS lookup
        domain_info = whois.whois(domain)

        # Extract specific details
        registrar = domain_info.registrar
        registrant_name = domain_info.name
        expiry_date = domain_info.expiration_date
        creation_date = domain_info.creation_date
        last_updated = domain_info.last_updated
        name_servers = domain_info.name_servers
        status = domain_info.status

        return {
            "Registrar": registrar,
            "Registrant Name": registrant_name,
            "Expiry Date": expiry_date,
            "Creation Date": creation_date,
            "Last Updated": last_updated,
            "Name Servers": name_servers,
            "Status": status
        }
    except socket.gaierror:
        return "Error: Unable to connect to WHOIS server. Please check your network connection."
    except whois.parser.PywhoisError as e:
        return "WHOIS lookup failed: " + str(e)
    except Exception as e:
        return "Error: " + str(e)

def main():
    try:
        domain = input("Enter the domain name you want to search: ")

        # Input validation
        if not domain:
            print("Please enter a valid domain name.")
            return

        # Display feedback
        print("Performing WHOIS lookup...")

        result = get_domain_info(domain)

        if isinstance(result, dict):
            for key, value in result.items():
                print(f"{key}: {value}")
        else:
            print(result)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")

if __name__ == "__main__":
    main()

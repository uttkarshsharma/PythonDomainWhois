import tkinter as tk
from tkinter import ttk, scrolledtext
import whois
import socket
import threading
import traceback
import re


def is_valid_domain(domain):
    """
    Validates if a domain string is properly formatted.
    """
    return re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", domain) is not None


def clean_domain_input(domain):
    """
    Cleans common domain entry mistakes like commas, spaces, and capitalization.
    Returns (corrected_domain, was_corrected)
    """
    original = domain
    domain = domain.strip().lower()
    domain = domain.replace(",", ".")
    domain = re.sub(r"[^a-zA-Z0-9.-]", "", domain)  # Remove special characters
    domain = re.sub(r"\.{2,}", ".", domain)         # Collapse multiple dots
    domain = domain.strip(".")

    return domain, domain != original


def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)

        if domain_info.domain_name is None:
            return f"No WHOIS record found for '{domain}'. The domain may be available or private."

        def format_value(value):
            if isinstance(value, list):
                return "\n".join(map(str, value))
            return str(value)

        return {
            "Domain Name": format_value(domain_info.domain_name),
            "Registrar": format_value(domain_info.registrar),
            "Creation Date": format_value(domain_info.creation_date),
            "Expiry Date": format_value(domain_info.expiration_date),
            "Last Updated": format_value(domain_info.updated_date),
            "Name Servers": format_value(domain_info.name_servers),
            "Status": format_value(domain_info.status),
            "Registrant Name": format_value(domain_info.name),
            "Organization": format_value(domain_info.org),
            "Address": format_value(domain_info.address),
            "City": format_value(domain_info.city),
            "State": format_value(domain_info.state),
            "Zipcode": format_value(domain_info.zipcode),
            "Country": format_value(domain_info.country),
        }
    except socket.gaierror:
        return "Error: Unable to connect. Please check your network connection."
    except whois.parser.PywhoisError as e:
        return f"WHOIS lookup failed for '{domain}'. It may not be a registered domain.\n\nDetails: {e}"
    except Exception:
        return f"An unexpected error occurred:\n\n{traceback.format_exc()}"


class WhoisApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WHOIS Lookup Tool")
        self.root.geometry("600x700")
        self.root.minsize(500, 400)

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Enter Domain Name:").pack(side=tk.LEFT, padx=(0, 5))

        self.domain_entry = ttk.Entry(input_frame, width=40)
        self.domain_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.domain_entry.bind("<Return>", self.start_lookup_thread)

        self.lookup_button = ttk.Button(input_frame, text="Lookup", command=self.start_lookup_thread)
        self.lookup_button.pack(side=tk.LEFT, padx=(5, 0))

        self.copy_button = ttk.Button(main_frame, text="Copy Results", command=self.copy_results_to_clipboard)
        self.copy_button.pack(pady=(0, 5))

        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, state='disabled', height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.configure(bg="#f0f0f0")

        self.results_text.tag_configure('bold', font=('TkDefaultFont', 10, 'bold'))
        self.results_text.tag_configure('error', foreground='red')

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding="2 5")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_lookup_thread(self, event=None):
        domain_raw = self.domain_entry.get().strip()
        if not domain_raw:
            self.update_results("Error: Please enter a domain name.", is_error=True)
            return

        domain, corrected = clean_domain_input(domain_raw)

        if not is_valid_domain(domain):
            self.update_results(f"Error: Invalid domain format after cleaning input. Tried: '{domain}'", is_error=True)
            return

        if corrected:
            self.domain_entry.delete(0, tk.END)
            self.domain_entry.insert(0, domain)
            self.status_var.set(f"Corrected input: {domain}")
        else:
            self.status_var.set(f"Performing WHOIS lookup for {domain}...")

        self.lookup_button.config(state='disabled')
        self.copy_button.config(state='disabled')

        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state='disabled')

        thread = threading.Thread(target=self.perform_lookup, args=(domain,))
        thread.daemon = True
        thread.start()

    def perform_lookup(self, domain):
        result = get_domain_info(domain)
        self.root.after(0, self.update_results, result)

    def update_results(self, result, is_error=False):
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)

        if isinstance(result, dict):
            for key, value in result.items():
                if value and value != 'None':
                    self.results_text.insert(tk.END, f"{key}:\n", 'bold')
                    self.results_text.insert(tk.END, f"  {value}\n\n")
            self.status_var.set("Lookup successful.")
        else:
            self.results_text.insert(tk.END, result, 'error' if is_error or "Error" in result else None)
            self.status_var.set("Lookup finished with an error." if "Error" in result else "Done.")

        self.results_text.config(state='disabled')
        self.lookup_button.config(state='normal')
        self.copy_button.config(state='normal')

    def copy_results_to_clipboard(self):
        content = self.results_text.get("1.0", tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.status_var.set("Results copied to clipboard.")


def main():
    root = tk.Tk()
    app = WhoisApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

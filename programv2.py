import tkinter as tk
from tkinter import ttk, scrolledtext
import whois
import socket
import threading


def get_domain_info(domain):
    try:
        # Perform WHOIS lookup
        domain_info = whois.whois(domain)

        # Check if the domain exists or if the query returned no data
        if domain_info.domain_name is None:
            return f"No WHOIS record found for '{domain}'. The domain may be available or private."

        # Extract specific details
        # The result can be a list or a single value, so we handle both cases.
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
        # This often means the domain does not exist
        return f"WHOIS lookup failed for '{domain}'. It may not be a registered domain.\n\nDetails: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"


class WhoisApp:
    """
    A GUI application for the WHOIS lookup tool using tkinter.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("WHOIS Lookup Tool")
        self.root.geometry("600x650")  # Set a default size
        self.root.minsize(500, 400)  # Set a minimum size

        # Configure the main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Input Section ---
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Enter Domain Name:").pack(side=tk.LEFT, padx=(0, 5))

        self.domain_entry = ttk.Entry(input_frame, width=40)
        self.domain_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.domain_entry.bind("<Return>", self.start_lookup_thread)  # Allow pressing Enter

        self.lookup_button = ttk.Button(input_frame, text="Lookup", command=self.start_lookup_thread)
        self.lookup_button.pack(side=tk.LEFT, padx=(5, 0))

        # --- Results Section ---
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, state='disabled', height=10)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        # Add a light grey background to the text area for better contrast
        self.results_text.configure(bg="#f0f0f0")

        # --- Status Bar ---
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding="2 5")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_lookup_thread(self, event=None):
        """
        Starts the WHOIS lookup in a separate thread to prevent the GUI from freezing.
        """
        domain = self.domain_entry.get().strip()
        if not domain:
            self.update_results("Error: Please enter a valid domain name.")
            return

        # Disable button and update status while processing
        self.lookup_button.config(state='disabled')
        self.status_var.set(f"Performing WHOIS lookup for {domain}...")

        # Clear previous results
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state='disabled')

        # Run the lookup in a new thread
        thread = threading.Thread(target=self.perform_lookup, args=(domain,))
        thread.daemon = True  # Allows main window to exit even if thread is running
        thread.start()

    def perform_lookup(self, domain):
        """
        The actual lookup logic that runs in the background thread.
        """
        result = get_domain_info(domain)
        # Schedule the GUI update to run in the main thread
        self.root.after(0, self.update_results, result)

    def update_results(self, result):
        """
        Updates the GUI with the lookup results. This method is called from the main thread.
        """
        self.results_text.config(state='normal')  # Enable writing
        self.results_text.delete(1.0, tk.END)

        if isinstance(result, dict):
            # Format and display the dictionary of results
            for key, value in result.items():
                if value and value != 'None':  # Only show fields with data
                    self.results_text.insert(tk.END, f"{key}:\n", ('bold',))
                    self.results_text.insert(tk.END, f"  {value}\n\n")
            self.status_var.set("Lookup successful.")
        else:
            # Display the error message
            self.results_text.insert(tk.END, result)
            self.status_var.set("Lookup finished with an error.")

        # Configure a 'bold' tag for the keys
        self.results_text.tag_configure('bold', font=('TkDefaultFont', 10, 'bold'))
        self.results_text.config(state='disabled')  # Disable writing

        # Re-enable the lookup button
        self.lookup_button.config(state='normal')


def main():
    root = tk.Tk()
    app = WhoisApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

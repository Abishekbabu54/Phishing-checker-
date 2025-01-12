from datetime import datetime
import whois
import re
import ssl
import socket
import urllib.parse
import requests
from urllib.parse import urlparse
import tldextract
import dns.resolver
import tkinter as tk
from tkinter import messagebox, scrolledtext


class PhishingScanner:
    def __init__(self):
        self.suspicious_terms = {
            'login', 'signin', 'verify', 'secure', 'account', 'update', 'banking',
            'confirm', 'paypal', 'password', 'credential', 'bitcoin', 'wallet',
            'authenticate', 'validation', 'session', 'recover', 'unlock'
        }
        self.legitimate_tlds = {
            '.com', '.org', '.edu', '.gov', '.net', '.mil', '.int', '.eu',
            '.us', '.uk', '.ca', '.au', '.de', '.fr', '.jp'
        }
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 3
        self.dns_resolver.lifetime = 3

    def calculate_domain_age(self, domain_name):
        try:
            # Fetch WHOIS information
            domain_info = whois.whois(domain_name)

            # Extract the creation date
            creation_date = domain_info.creation_date

            # Handle cases where the creation date might be a list
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            # Ensure creation_date is valid
            if not creation_date:
                return None, "Unable to retrieve creation date"

            # Calculate the difference
            current_date = datetime.now()
            domain_age_days = (current_date - creation_date).days

            # Return age in days
            return domain_age_days, None
        except Exception as e:
            return None, f"Error calculating domain age: {str(e)}"

    def analyze_url(self, url: str) -> dict:
        results = {
            'url': url,
            'risks': [],
            'risk_score': 0,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'security_features': {},
            'recommendations': []
        }

        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                raise ValueError("Invalid URL format")

            # Extract domain information
            extracted_info = tldextract.extract(url)
            domain = f"{extracted_info.domain}.{extracted_info.suffix}"

            # Check domain age
            domain_age_days, error = self.calculate_domain_age(domain)
            if domain_age_days is not None:
                results['security_features']['domain_age_days'] = domain_age_days
                if domain_age_days < 30:
                    results['risks'].append(f"Domain is only {domain_age_days} days old")
                    results['risk_score'] += 25
                    results['recommendations'].append("Be cautious of newly registered domains")
            else:
                results['risks'].append(error or "Unable to verify domain age")
                results['risk_score'] += 15

            # Other analysis (e.g., HTTPS, SSL, DNS records) can be added here.

        except Exception as e:
            results['risks'].append(f"Error during analysis: {str(e)}")
            results['risk_score'] = 100
            results['risk_level'] = 'Error'
            results['recommendations'].append('Unable to complete full analysis')

        # Calculate final risk level
        results['risk_level'] = (
            'Critical' if results['risk_score'] >= 80 else
            'High' if results['risk_score'] >= 60 else
            'Medium' if results['risk_score'] >= 30 else
            'Low'
        )

        return results


class App:
    def __init__(self, root):
        self.scanner = PhishingScanner()
        self.root = root
        self.root.title("Phishing URL Scanner")

        self.url_label = tk.Label(root, text="Enter URL:")
        self.url_label.pack()

        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack()

        self.analyze_button = tk.Button(root, text="Analyze", command=self.analyze_url)
        self.analyze_button.pack()

        self.result_text = scrolledtext.ScrolledText(root, width=60, height=20)
        self.result_text.pack()

    def analyze_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL.")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Analyzing...\n")
        self.root.update()

        results = self.scanner.analyze_url(url)
        self.display_results(results)

    def display_results(self, results):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scan Time: {results['scan_time']}\n")
        self.result_text.insert(tk.END, f"URL: {results['url']}\n")
        self.result_text.insert(tk.END, f"Risk Level: {results['risk_level']}\n")
        self.result_text.insert(tk.END, f"Risk Score: {results['risk_score']}\n\n")

        self.result_text.insert(tk.END, "Risks:\n")
        for risk in results['risks']:
            self.result_text.insert(tk.END, f"- {risk}\n")

        self.result_text.insert(tk.END, "\nRecommendations:\n")
        for rec in results['recommendations']:
            self.result_text.insert(tk.END, f"- {rec}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()

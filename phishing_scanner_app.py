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
    suspicious_terms = ['login', 'secure', 'account', 'update', 'verify']
    legitimate_tlds = ['com', 'org', 'net', 'gov', 'edu']

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

            # Check HTTPS
            if not url.startswith('https://'):
                results['risks'].append('Not using HTTPS encryption')
                results['risk_score'] += 20
                results['recommendations'].append('Use HTTPS for secure connections')

            # Check for suspicious terms in domain name
            domain_parts = extracted_info.domain.lower().split('-')
            found_terms = [term for term in self.suspicious_terms if any(term in part for part in domain_parts)]
            
            if found_terms:
                results['risks'].append(f"Domain contains suspicious terms: {', '.join(found_terms)}")
                results['risk_score'] += len(found_terms) * 10
                results['recommendations'].append("Domain name contains terms commonly used in phishing")

            # Check for hyphens in domain (common in phishing URLs)
            if '-' in extracted_info.domain:
                results['risks'].append('Domain contains hyphens')
                results['risk_score'] += 15
                results['recommendations'].append('Multiple hyphens in domain names are common in phishing URLs')

            # Check domain age
            domain_age_days, error = self.calculate_domain_age(domain)
            if domain_age_days is not None:
                results['security_features']['domain_age_days'] = domain_age_days
                if domain_age_days < 30:
                    results['risks'].append(f"Domain is only {domain_age_days} days old")
                    results['risk_score'] += 25
                    results['recommendations'].append("Be cautious of newly registered domains")
            else:
                results['risks'].append("Unable to verify domain age")
                results['risk_score'] += 15
                results['recommendations'].append("Domain age verification failed - exercise caution")

            # Check TLD
            if not any(domain.endswith(tld) for tld in self.legitimate_tlds):
                results['risks'].append('Unusual domain ending')
                results['risk_score'] += 15
                results['recommendations'].append('Verify legitimacy of unusual TLDs')

            # If example.com, add warning
            if 'example.com' in domain:
                results['risks'].append('Using example.com domain - likely a test or fake URL')
                results['risk_score'] += 50
                results['recommendations'].append('This appears to be a test/example URL')

            # Calculate final risk level
            results['risk_level'] = (
                'Critical' if results['risk_score'] >= 80 else
                'High' if results['risk_score'] >= 60 else
                'Medium' if results['risk_score'] >= 30 else
                'Low'
            )

            # If no risks found but suspicious patterns exist
            if not results['risks']:
                results['risks'].append('No immediate risks detected')

        except Exception as e:
            results['risks'].append(f"Error during analysis: {str(e)}")
            results['risk_score'] = 100
            results['risk_level'] = 'Error'
            results['recommendations'].append('Unable to complete full analysis')

        return results

    def calculate_domain_age(self, domain: str) -> tuple:
        try:
            whois_info = whois.whois(domain)
            creation_date = whois_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now() - creation_date).days
            return age_days, None
        except Exception as e:
            return None, str(e)


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

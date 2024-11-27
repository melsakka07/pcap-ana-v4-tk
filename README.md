# 📞 SIP Packet Analyzer v2.0

A Python-based GUI application for analyzing SIP (Session Initiation Protocol) packets from PCAP files. This tool provides a user-friendly interface to extract and analyze VoIP communications data, with a focus on network information headers. 🔍

## ✨ Key Features

### Analysis Capabilities
- 📊 Processes PCAP files containing SIP traffic
- 🔍 Extracts and analyzes:
  - REGISTER messages
  - INVITE messages
  - Critical SIP headers:
    - To header
    - Route information
    - P-Access-Network-Info
    - Cellular-Network-Info
- 📈 Generates detailed message statistics

### User Interface
- 🖥️ Modern, centered GUI design
- 🎯 Easy directory selection for input/output
- 📊 Real-time progress tracking
- 💻 Live console output
- ⚡ Responsive feedback

### Output Features
- 📑 Two-part analysis reports:
  1. Statistical Summary
     - Total packet counts
     - Message type distribution
     - Header availability statistics
  2. Detailed Message Information
     - Message type
     - Timestamp
     - Selected headers only
- 🔄 Automatic file organization

## 📊 Analysis Output

### Summary Report
- Analysis timestamp
- File information
- Message counts:
  - Total SIP packets
  - REGISTER messages
  - INVITE messages
- Header availability:
  - P-Access-Network-Info in REGISTER/INVITE
  - Cellular-Network-Info in REGISTER/INVITE

### Detailed Message Analysis
For each REGISTER/INVITE message:
- Message Type
- Timestamp
- To header
- Route information
- P-Access-Network-Info
- Cellular-Network-Info

## 🛠️ System Requirements

### Essential Software
- 🐍 Python 3.x
- 🦈 Wireshark/TShark (latest version)
- 📦 Required Python packages:
  - pyshark
  - tqdm
  - tkinter (included with Python)

### Hardware Recommendations
- 💾 Minimum 4GB RAM
- 💽 Sufficient disk space for PCAP files
- 🖥️ 1080p display or higher (for optimal GUI experience)

## 💻 Quick Start Guide

1. **Installation**
   ```bash
   # Clone repository
   git clone [repository-url]
   cd sip-analyzer

   # Set up virtual environment
   python -m venv .venv
   .\.venv\Scripts\activate  # Windows
   source .venv/bin/activate # Linux/Mac

   # Install dependencies
   pip install -r requirements.txt
   ```

2. **Running the Application**
   ```bash
   python sip-script.py
   ```

3. **Using the Interface**
   - Select input folder containing PCAP files
   - Choose output directory for analysis
   - Click "Start Analysis"
   - Monitor progress in real-time
   - View results in the specified output folder

## ⚠️ Troubleshooting

Common Issues:
- 🚫 "TShark not found": Ensure Wireshark is installed and in PATH
- 📁 "No PCAP files": Check input directory
- 💾 "Memory error": Process smaller batches
- ⏱️ "Slow processing": Normal for large files

## 🔧 Advanced Configuration

### Performance Tuning
- Adjust batch processing size
- Modify console output frequency
- Configure memory management

### Custom Analysis
- Edit header extraction
- Modify output format
- Add custom filters

## 📚 Resources

- [SIP Protocol RFC 3261](https://tools.ietf.org/html/rfc3261)
- [Wireshark Docs](https://www.wireshark.org/docs/)
- [pyshark Documentation](https://kiminewt.github.io/pyshark/)

## 📄 License

MIT License - See LICENSE file for details

## 👥 Support

Created with ❤️ by M. ElSakka

For support:
- 📧 Email: support@astravision.ai
- 💬 Issues: GitHub issue tracker
- 📱 Twitter: @AstraVision_AI

---

**Note**: This tool is optimized for enterprise-level SIP analysis. For basic packet analysis, simpler tools may be more appropriate.
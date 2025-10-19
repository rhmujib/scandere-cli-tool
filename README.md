# Vulnerability

# 🕵️‍♂️ Scandere 

## Overview
**Scandere** is a Python-based Command-Line Interface (CLI) tool designed for web endpoint discovery, vulnerability scanning, and HTML report generation.  
It provides developers and cybersecurity enthusiasts with a lightweight, efficient, and easy-to-use interface for quick security assessments.

---

## ✨ Features
- 🚀 Easy-to-use command-line interface  
- 🌐 Automated web endpoint discovery  
- 🧠 Web flaw and vulnerability checks  
- 🧾 HTML report generation  
- 🧩 Modular design with reusable utilities  
- 🧪 Built-in unit tests for reliability  

---

## 📦 Installation

### 1. Clone the Repository
First, clone the repository from GitHub:

```bash
git clone https://github.com/rhmujib/scandere-cli-tool.git
cd scandere-cli-tool

```

# Create a Virtual Environment (recommended)

    python -m venv venv
    source venv/bin/activate        # On macOS/Linux
    venv\Scripts\activate           # On Windows

# Install Dependencies

    pip install -r requirements.txt

# 💻 Usage

Option 1: Run using Python

    | Flag             | Example          | Description                                                                                                          |
    | ---------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------- |
    
    | `--output`       | `--output html`  | Choose output format: `json` (default) or `html`. Generates `report.json` or `report.html`.                          |
    
    | `--no-discover`  | `--no-discover`  | Skip automatic endpoint discovery and scan only the provided target URL.                                             |
    
    | `--confirm`      | `--confirm`      | Enables deeper vulnerability verification. Performs extra checks (boolean-based SQLi and high-confidence XSS tests). |
   
    | `--time-confirm` | `--time-confirm` | Runs **time-based SQLi confirmation** (⚠️ slower & more intrusive — use only with permission).                       |
    
    | `--fast`         | `--fast`         | Enables **fast scan mode** — fewer XSS payloads and reduced timeout for quicker results (useful for large sites).    |


Option 2: Run the CLI directly (after setup)

    Once installed globally or added to PATH, you’ll be able to run:        

        scandere

 # 🧰 Project Structure 

            scandere/
                │
                ├── cli_tool/
                │   ├── __init__.py
                │   ├── main.py
                │   ├── utils.py
                │   └── report_generator.py
                │
                ├── tests/
                │   ├── test_utils.py
                │   └── test_main.py
                │
                ├── requirements.txt
                ├── README.md
                └── LICENSE
 # 🤝 Contributing

    Contributions are welcome!
    If you’d like to improve the tool, please follow these steps:

    Fork the repository

    Create a new branch

This project is licensed under the MIT License.
See the LICENSE

# 🪪 License

This project is licensed under the MIT License.
See the LICENSE

# 🧑‍💻 Author

    Cybermj (Mujeeb Ur Rehman)
    GitHub: @rhmujib
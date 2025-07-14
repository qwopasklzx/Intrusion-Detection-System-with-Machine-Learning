# Intrusion Detection System with Machine Learning

Prerequisites
- Make sure you have Python installed on your computer.
- Install Wireshark if you haven’t already.

Install & Configure TShark
1. Install Wireshark
   Download and install Wireshark from: https://www.wireshark.org/
2. Set up TShark Environment Variables
- Press Win + S and search for “Advanced System Settings”.
- Click “Environment Variables…”.
- In the “User variables” section, double-click Path.
- Click “New”, then add:
    C:\Program Files\Wireshark\
- Click “New” again, then add:
    C:\Program Files\Wireshark\tshark.exe
- Click OK, then OK, then OK to save.
- Restart your computer to apply the changes.

Login credentials
Usename: jsmith
password: ABC@abc123!

Setup Python Virtual Environment
1. Create a new project folder
2. Open cmd
     - navigate to the folder
3. Create a virtual environment:
     - python -m venv app
4. Activate the virtual environment:
     - app\Scripts\activate

Install Dependencies & Run the App
1. Navigate to the folder
2. Install the required packages
     - pip install -r requirements.txt
3. Run the Streamlit app:
     - python -m streamlit run main.py


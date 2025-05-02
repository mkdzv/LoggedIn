# LoggedIn
LoggedIn is a log analysis system designed to process Windows Event Logs and identify suspicious login attempts. This tool includes automated reporting features to reduce manual log review time for security teams. I built the tool with Python and integrated it with Splunk, I also added NumPy for analysis and Matplotlib for data visualization.

## Features
- **Automated Logs**: Automated parsing of Windows Security Event Logs (Event ID 4624, 4625, etc.)
- **Splunk Integration**: Splunk integration for log management
- **Numpy Analysis**: Statistical analysis using NumPy
- **Matplotlib Visualization**: Data visualization with Matplotlib
- **Attack Detection**: Detection of brute force attacks and suspicious login attempts
- **Timely Detection**: Time based detection (off-hours login activity)
- **Data Analysis**: Failed login attempt analysis


## How it works
The user runs the program
The program outputs the logs and details of all 100 logs that were processed
The user analyzes the logs and statistics to see what happened
The user reads through the data visualization 

## Installation
1. Download the lastest version of Python on your device
2. Install all dependencies needed `pip install numpy matplotlib splunk-sdk`
3. Download all files from the LoggedIn folder
4. Save files in the same folder

## Usage
1. Open the IDE of your choice (VScode, Notepad, etc)
2. Open the folder with the files
3. Open the terminal and type python loggedin.py
4. Run the program
5. Look through all the logs
  
## Example
=== Windows Event Log Security Analysis ===
Generating 100 sample logs with realistic patterns...
Log file created at: C:\Users\asus\Desktop\File\Personal\Projects\LoggedIn\app\sample_events.log
Processing logs...

=== Analysis Results ===

Failed login attempts by user:
- hacker@bad.com: 9 attempts
- admin123@domain.com: 4 attempts
- guest@domain.com: 5 attempts
- john.doe@domain.com: 2 attempts
- root@domain.com: 2 attempts
- helpdesk@domain.com: 1 attempts
- service_acct@domain.com: 1 attempts
- scanner@attack.com: 3 attempts
- test@domain.com: 2 attempts
- backup_admin@domain.com: 1 attempts
- user1@domain.com: 1 attempts

Suspicious users detected:
- hacker@bad.com
- guest@domain.com
- admin@domain.com
- root@domain.com
- admin123@domain.com
- backup_admin@domain.com
- test@domain.com

=== Security Alerts ===

[!] Brute Force Attempts Detected:
- User hacker@bad.com failed 9 login attempts

[!] Suspicious Users Detected:
- Suspicious user account: hacker@bad.com
- Suspicious user account: guest@domain.com
- Suspicious user account: admin@domain.com
- Suspicious user account: root@domain.com
- Suspicious user account: admin123@domain.com
- Suspicious user account: backup_admin@domain.com
- Suspicious user account: test@domain.com

[!] Unusual Activity Detected:
- Unusual login hours detected: 0, 1, 2, 3, 4:00
- User admin@domain.com logged in from multiple computers: SRV02, DC01, SRV01, LAPTOP01, WS01
- User helpdesk@domain.com logged in from multiple computers: WS01, SRV02, DESKTOP01, SRV01
- User service_acct@domain.com logged in from multiple computers: SRV02, DC01, SRV01, WS02, DESKTOP01, LAPTOP01
- User hacker@bad.com logged in from multiple computers: DC01, WS02, LAPTOP01, SRV01
- User backup_admin@domain.com logged in from multiple computers: SRV02, WS02, DESKTOP01, DC02, LAPTOP01, WS01
- User user1@domain.com logged in from multiple computers: SRV02, DC01, SRV01, DESKTOP01, LAPTOP01, WS01
- User admin123@domain.com logged in from multiple computers: DESKTOP01, WS01, DC02
- User john.doe@domain.com logged in from multiple computers: SRV02, DC01, WS02, SRV01, DC02, WS01
- User guest@domain.com logged in from multiple computers: DC01, SRV02, SRV01, LAPTOP01

=== Event Statistics ===
Total events processed: 100
Event types:
- 4624 (Successful Login): 57
- 4625 (Failed Login): 31
- 4672 (Admin Login): 10
- 4634 (Logout): 2

=== Generating Visualizations ===
Failed logins chart saved as 'failed_logins.png'
Login timeline chart saved as 'login_timeline.png'
Event distribution chart saved as 'event_distribution.png'
Computer activity chart saved as 'computer_activity.png'
Hourly activity chart saved as 'hourly_activity.png'

Analysis complete! All visualizations have been saved as PNG files.

## Contribute
- Fork the repository.
- Create a new branch (`git checkout -b feature-branch`).
- Commit your changes (`git commit -m "Add new feature"`).
- Push to your forked repository (`git push origin feature-branch`).
- Create a pull request with your proposed changes.

## License
MIT License

Copyright (c) 2025 mkdzv

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

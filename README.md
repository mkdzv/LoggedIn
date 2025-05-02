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

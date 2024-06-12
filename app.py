from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import concurrent.futures
import os

app = Flask(__name__, template_folder='./templates', static_folder='./static')

# Global variables to store progress messages and stop process flag
progress_messages = []
stop_process = False

# Define VirusTotal API key
VIRUSTOTAL_API_KEY = '658b2d99745d227804de1ce8e498e7e6d8e5c7325167d71c37315ca7d1c6263a' 

# URL Scanner functionality
def check_url_malicious(url, api_key):
    endpoint = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': url}
    response = requests.get(endpoint, params=params)
    result = response.json()
    if response.status_code == 200:
        if result['response_code'] == 1:
            detections = result['scans']
            detected_vendors = []
            for vendor_name, detection in detections.items():
                if detection['detected']:
                    detected_vendors.append((vendor_name, detection['result']))
            return render_template('scan_url_result.html', detected_vendors=detected_vendors)
        else:
            return "Error: " + result['verbose_msg']
    else:
        return "Failed to retrieve results. Status code: " + str(response.status_code)

# File Scanner functionality
def scan_file_with_virustotal(file):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': file}
    params = {'apikey': VIRUSTOTAL_API_KEY}
    response = requests.post(url, files=files, params=params)
    result = response.json()
    return result

def get_file_scan_report(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    result = response.json()
    return result

# Vulnerable Directory Finder functionality
def check_directory(method, url, directory):
    global stop_process
    if stop_process:
        return

    if not url.endswith('/'):
        url += '/'

    target_url = url + directory
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    try:
        response = requests.request(method, target_url, headers=headers, timeout=5)  # Timeout after 5 seconds
        if response.status_code == 200:
            progress_messages.append({
                'method': method,
                'message': f"Directory found: <a href='{target_url}' style='color: green;' target='_blank'>{target_url}</a>",
                'status': 'success',
                'url': target_url,
                'response_code': response.status_code
            })
        else:
            progress_messages.append({
                'method': method,
                'message': f"Checking directory: {target_url} - Response code: {response.status_code}",
                'status': 'info',
                'url': target_url,
                'response_code': response.status_code
            })
    except requests.RequestException as e:
        progress_messages.append({
            'method': method,
            'message': f"Failed to check directory {target_url}: {e}",
            'status': 'danger',
            'url': target_url,
            'response_code': 'N/A'
        })

def dirb(method, url, num_threads=50):
    global stop_process
    # Get the directory of the current Python script
    script_dir = os.path.dirname(__file__)
    # Define the path to the wordlist file
    wordlist_path = os.path.join(script_dir, 'wordlist.txt')

    with open(wordlist_path, 'r') as f:
        directories = [line.strip() for line in f]

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(check_directory, method, url, directory) for directory in directories]
        for future in concurrent.futures.as_completed(futures):
            pass  # Wait for all tasks to complete
            if stop_process:
                break

# Routes for different functionalities
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form['url']
    result = check_url_malicious(url, VIRUSTOTAL_API_KEY)
    return result

@app.route('/scan_file', methods=['POST'])
def scan_file():
    file = request.files['file']
    if file:
        scan_result = scan_file_with_virustotal(file)
        if scan_result.get('response_code') == 1:
            resource = scan_result.get('resource')
            report_result = get_file_scan_report(resource)
            if report_result.get('positives', 0) > 0:
                detections = report_result.get('scans', {})
                detected_vendors = [(vendor, data.get('result', '')) for vendor, data in detections.items() if data.get('detected')]
                return render_template('scan_file_result.html', detected_vendors=detected_vendors)
            else:
                return "The file is clean."
        else:
            return "Failed to scan the file."
    else:
        return "No file uploaded"

@app.route('/vul_scanner', methods=['POST'])
def vul_scanner():
    global progress_messages, stop_process
    url = request.form['url']
    if not url.endswith('/'):
        url += '/'
    num_threads = int(request.form['threads'])
    progress_messages = []  # Reset progress messages
    stop_process = False
    method = request.form['method']  # Get the selected HTTP method
    dirb(method, url, num_threads)
    return redirect(url_for('vul_result'))  # Redirect to the result page after processing

@app.route('/progress')
def get_progress():
    global progress_messages
    return jsonify(progress_messages)

@app.route('/stop')
def stop():
    global stop_process
    stop_process = True
    return redirect(url_for('vul_result'))  # Redirect to the result page after stopping the process

@app.route('/vul_result')
def vul_result():
    return render_template('vul_result.html', progress=progress_messages)

if __name__ == '__main__':
    app.run(debug=True)

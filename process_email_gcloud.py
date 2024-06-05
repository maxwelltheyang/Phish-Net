# This is the gcloud version, will not work locally.

import base64
import functions_framework
import json
import os
from googleapiclient.discovery import build
from google.cloud import secretmanager
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import re
from urllib.parse import urlparse, urlunparse, urljoin
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import tldextract
import socket
import subprocess
import dns.resolver
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np

client = secretmanager.SecretManagerServiceClient()
response = client.access_secret_version(request={"name": "projects/mystic-span-415322/secrets/AUTH_TOKEN/versions/latest"})
AUTH_TOKEN = response.payload.data.decode("UTF-8")
response_2 = client.access_secret_version(request={"name": "projects/mystic-span-415322/secrets/PAGERANK_API/versions/latest"})
PAGERANK_API = response_2.payload.data.decode("UTF-8")
response_3 = client.access_secret_version(request={"name": "projects/mystic-span-415322/secrets/OPEN_SEARCH/versions/latest"})
OPEN_SEARCH = response_3.payload.data.decode("UTF-8")
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def create_service():
    global SCOPES, AUTH_TOKEN
    credentials = Credentials.from_authorized_user_info(json.loads(AUTH_TOKEN), SCOPES)
    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            client = secretmanager.SecretManagerServiceClient()
            parent = f"projects/mystic-span-415322/secrets/AUTH_TOKEN"
            payload = credentials.to_json().encode('UTF-8')
            client.add_secret_version(parent=parent, payload={'data': payload})
    service = build('gmail', 'v1', credentials=credentials)
    return service

def upload_files():
    storage_client = storage.Client()
    bucket = storage_client.bucket('phish-files')
    ml = bucket.blob('phishing_ml.h5')
    ml.download_to_filename('/tmp/phishing_ml.h5')
    domains = bucket.blob('phishing-domains.txt')
    domains.download_to_filename('/tmp/phishing-domains.txt')
    scaler = bucket.blob('scaler.save')
    scaler.download_to_filename('/tmp/scaler.save')
    dom1 = bucket.blob('top-100000-domains.txt')
    dom1.download_to_filename('/tmp/top-100000-domains.txt')
    dom2 = bucket.blob('top-1000000-domains.txt')
    dom2.download_to_filename('/tmp/top-1000000-domains.txt')

def normalize_url(url):
    parsed_url = urlparse(url.lower())
    if parsed_url.scheme == '':
        new_netloc = parsed_url.path
        new_path = ''
        parsed_url = parsed_url._replace(scheme='http', netloc=new_netloc, path=new_path)
    return parsed_url

def port_status(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((host, port))
    except socket.error:
        return 0
    else:
        return 1
    finally:
        sock.close()

def extract_domain(url):
    parsed_url = tldextract.extract(url)
    return f"{parsed_url.domain}.{parsed_url.suffix}"

def calculate_external(url, html):
    page_domain = extract_domain(url)
    external_objects = 0
    total_objects = 0
    soup = BeautifulSoup(html, 'html.parser')
    tags = soup.find_all(['img', 'script', 'link', 'iframe', 'audio', 'video', 'source'])
    for tag in tags:
        attr = None
        if tag.name == 'img':
            attr = 'src'
        elif tag.name == 'script':
            attr = 'src'
        elif tag.name == 'link':
            attr = 'href'
        elif tag.name == 'iframe':
            attr = 'src'
        elif tag.name in ['audio', 'video']:
            attr = 'src'
        elif tag.name == 'source':
            attr = 'src'
        if attr and tag.has_attr(attr):
            obj_url = urljoin(url, tag[attr])
            obj_domain = extract_domain(obj_url)
            total_objects += 1
            if obj_domain != page_domain:
                external_objects += 1
    return (external_objects / total_objects) + 0.0

def calculate_anchor(url,html):
    page_domain = extract_domain(url)
    external_objects = 0
    total_objects = 0
    soup = BeautifulSoup(html, 'html.parser')
    tags = soup.find_all('a', href=True)
    non_webpage_anchors = ['#', '#content', '#skip', 'javascript:void(0)']
    for tag in tags:
        href = tag['href']
        if href in non_webpage_anchors:
            continue
        obj_url = urljoin(url, href)
        obj_domain = extract_domain(obj_url)
        total_objects += 1
        if obj_domain != page_domain:
            external_objects += 1
    return (external_objects / total_objects) + 0.0

def calculate_metadata(url, html):
    page_domain = extract_domain(url)
    external_objects = 0
    total_objects = 0
    soup = BeautifulSoup(html, 'html.parser')
    tags = soup.find_all(['meta', 'script', 'link'])

    for tag in tags:
        attr = None
        if tag.name == 'meta' and tag.has_attr('content'):
            attr = 'content'
        elif tag.name == 'script' and tag.has_attr('src'):
            attr = 'src'
        elif tag.name == 'link' and tag.has_attr('href'):
            attr = 'href'
        if attr:
            link_url = urljoin(url, tag[attr])
            link_domain = extract_domain(link_url)
            total_objects += 1
            if link_domain != page_domain:
                external_objects += 1

    return (external_objects / total_objects) + 0.0

def calculate_sfh(url, html):
    page_domain = extract_domain(url)
    soup = BeautifulSoup(html, 'html.parser')
    tags = soup.find_all(['form'])
    results = []
    for tag in tags:
        action = tag.get('action')
        if not action or action.strip().lower() == "about:blank":
            results.append(1)
        else:
            full_url = urljoin(url, action)
            action_domain = extract_domain(full_url)
            if action_domain != page_domain:
                results.append(0)
            else:
                results.append(-1)
    return results

def check_mailto(html):
    soup = BeautifulSoup(html, 'html.parser')
    mailto_links = soup.find_all('a', href=True)
    for link in mailto_links:
        if link['href'].startswith('mailto:'):
            return 1
    return -1

def mouse_over(html):
    soup = BeautifulSoup(html, 'html.parser')
    elements_with_onmouseover = soup.find_all(onmouseover=True)
    for element in elements_with_onmouseover:
        onmouseover_content = element['onmouseover']
        if re.search(r'status\s*=', onmouseover_content, re.IGNORECASE):
            return 1
    return -1

def right_click(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string:
            if re.search(r'event\.button\s*==\s*2', script.string):
                return 1
            if re.search(r'event\.button\s*===\s*2', script.string):
                return 1
            if re.search(r'contextmenu', script.string):
                return 1
    return -1

def check_popups(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string:
            if 'window.open' in script.string or 'window.showModalDialog' in script.string:
                if re.search(r'<input[^>]*type=["\']?text["\']?', script.string) or re.search(r'<textarea', script.string):
                    return 1
    return -1

def get_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            return -1
    except dns.resolver.NoAnswer:
        return 1
    except dns.resolver.NXDOMAIN:
        return 1
    except dns.exception.DNSException as e:
        return 1
    
def get_top_websites(url):
    with open('/tmp/top-100000-domains.txt', 'r') as file:
        file_content = file.read()
        if url in file_content:
            return -1
    with open('/tmp/top-1000000-domains.txt', 'r') as file:
        file_content = file.read()
        if url in file_content:
            return 0
        else:
            return 1
        
def get_page_rank(domain):
    url = f"https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}"
    headers = {
        'API-OPR': PAGERANK_API
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    return data["response"][0]["page_rank_decimal"], data['response'][0].get('rank', 0)

def get_google_index(url):
    cx = '44f8c8f81b8754070'
    search_url = f"https://www.googleapis.com/customsearch/v1?q=site:{url}&key={OPEN_SEARCH}&cx={cx}"
    try:
        response = requests.get(search_url)
        response.raise_for_status()
        data = response.json()
        results = data.get('searchInformation', {}).get('totalResults', '0') != '0'
        return -1
    except Exception as e:
        return 1

def check_phish(url):
    with open('/tmp/phishing-domains.txt', 'r') as file:
        file_content = file.read()
        if url in file_content:
            return 1
        else:
            return -1
        
def extract_attributes(url):
    # 1 is considered phishing
    # 0 is considered suspicious
    # -1 is considered legitimate 
    attributes = {}
    raw_url = urlunparse(url)
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    attributes["ip"] = 1 if ip_pattern.search(url.netloc) else -1
    attributes["len"] = -1 if len(raw_url) < 54 else (0 if len(raw_url) >= 54 and len(raw_url) <= 75 else 1)
    shorteners = ["bit.ly","goo.gl","tinyurl.com","is.gd","t.co","ow.ly","buff.ly","adf.ly","bit.do","mcaf.ee","rebrand.ly","buff.ly","cutt.ly","cli.re","shorte.st","bl.ink"]
    attributes["short"] = 1 if any(shortener in url.netloc for shortener in shorteners) else -1
    attributes["@"] = 1 if "@" in raw_url else -1
    attributes["//"] = 1 if (url.scheme != "http" and url.scheme != "https") else -1
    attributes["-"] = 1 if "-" in url.netloc else -1
    attributes["domain"] = -1 if url.netloc.count(".") == 2 else (0 if url.netloc.count(".") == 3 else 1)
    dom = whois.whois(url.netloc).creation_date
    domain_age = dom[0] if isinstance(dom, list) else dom
    if (domain_age is None):
        attributes["trust"] = 1
    else:
        diff = abs((datetime.now() - domain_age).days)
        attributes["trust"] = -1 if (diff >= 365 and url.scheme == "https") else (0 if url.scheme == "https" else 1)
    exp = whois.whois(url.netloc).expiration_date
    exp_date = exp[0] if isinstance(exp, list) else exp
    if (exp_date is None):
        attributes["expiration"] = 1
    else:
        exp_diff = abs((datetime.now() - exp_date).days)
        attributes["expiration"] = -1 if exp_diff >= 365 else 1
    #page_domain = extract_domain(raw_url)
    response = requests.get(raw_url)
    response.raise_for_status()
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    icon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
    favicon_url = None
    favicon_domain = None
    if icon_link and icon_link.get('href'):
        favicon_url = urljoin(raw_url, icon_link['href'])
        favicon_domain = tldextract.extract(favicon_url).registered_domain
    page_domain = tldextract.extract(raw_url).registered_domain
    attributes["favicon"] = 1 if page_domain == favicon_domain else -1
    ports = [21,22,23,80,443,445,1433,1521,3306,3389]
    pref = [0,0,0,1,1,0,0,0,0,0]
    actual = []
    for port in ports:
        actual.append(port_status(url.hostname, port))
    attributes["ports"] = -1 if pref == actual else 1
    attributes["https"] = 1 if "https" in url.netloc else -1
    ratio = calculate_external(raw_url, html)
    attributes["external"] = -1 if ratio < 0.22 else (0 if ratio >= 0.22 and ratio < 0.61 else 1)
    anchor_ratio = calculate_anchor(raw_url, html)
    attributes["anchor"] = -1 if anchor_ratio < 0.31 else (0 if anchor_ratio >= 0.31 and anchor_ratio <= 0.67 else 1)
    metadata_ratio = calculate_metadata(raw_url, html)
    attributes["metadata"] = -1 if metadata_ratio < 0.17 else (0 if metadata_ratio >= 0.17 and metadata_ratio <= 0.81 else 1)
    results = calculate_sfh(raw_url, html)
    attributes["sfh"] = 1 if 1 in results else (0 if 0 in results else -1)
    attributes["mailto"] = 1 if "mail(" in response.text or check_mailto(html) == 1 else -1
    domm = whois.whois(url.netloc).domain_name
    domain_name = domm[0] if isinstance(domm, list) else domm
    domain_name = domain_name.lower()
    attributes["abnormal"] = -1 if domain_name in raw_url else 1
    attributes["redirect"] = -1 if len(response.history) <= 1 else (0 if len(response.history) >= 2 and len(response.history) < 4 else 1)
    attributes["mouse-over"] = mouse_over(html)
    attributes["right-click"] = right_click(html)
    attributes["popups"] = check_popups(html)
    iframes = soup.find_all('iframe')
    attributes["iframe"] = -1 if iframes is None else 1
    attributes["age"] = -1 if diff >= 182.5 else 1
    attributes["dns"] = get_dns_records(domain_name)
    attributes["traffic"] = get_top_websites(domain_name)
    total_rank = get_page_rank(raw_url)
    page_rank = total_rank[0]
    links = total_rank[1]
    if (page_rank == ''):
        attributes["page-rank"] = 1
    else:
        attributes["page-rank"] = 1 if float(page_rank) < 0.2 else -1
    attributes["google-index"] = get_google_index(raw_url)
    if (links == ''):
        attributes["links"] = 1
    else:
        attributes["links"] = 1 if int(links) == 0 else (0 if int(links) <= 2 else -1)
    attributes["top-domains"] = check_phish(raw_url)
    return attributes

def predict_data(attribute, model, scaler):
    new_data = np.array(list(attribute.values()))
    #print(new_data)
    if new_data.ndim == 1:
        new_data = new_data.reshape(1, -1)
    new_data_scaled = scaler.transform(new_data)
    predictions = model.predict(new_data_scaled)
    predicted_classes = predictions.argmax(axis=1)
    return predicted_classes

def process_email():
    upload_files()
    service = create_service()
    result = service.users().messages().list(userId='me', maxResults=1, q="").execute()
    messages = result.get('messages', [])
    email_id = messages[0]['id']
    message = service.users().messages().get(userId='me', id=email_id).execute()
    payload = message['payload']
    parts = payload.get('parts')
    email_body = ""
    if parts:
        for part in parts:
            if part['mimeType'] == 'text/plain':
                email_body += base64.urlsafe_b64decode(part['body']['data']).decode('UTF-8')
            elif part['mimeType'] == 'multipart/alternative':
                for subpart in part['parts']:
                    if subpart['mimeType'] == 'text/plain':
                        email_body += base64.urlsafe_b64decode(subpart['body']['data']).decode('UTF-8')
    urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+)', email_body)
    print(urls)
    parsed_urls = [normalize_url(url) for url in urls]
    attributes = [extract_attributes(url) for url in parsed_urls]
    model = load_model('/tmp/phishing_ml.h5')
    scaler = joblib.load('/tmp/scaler.save')
    data = [predict_data(attribute, model, scaler) for attribute in attributes]
    print(data)
    if any(np.any(arr == 1) for arr in data):
        service.users().messages().modify(userId='me', id=email_id, body={'addLabelIds': ['SPAM'], 'removeLabelIds': []}).execute()
        print("email with phishing link moved to spam succesfully")
    return data

    

@functions_framework.cloud_event
def hello_pubsub(cloud_event):
    msg_json = json.loads(base64.b64decode(cloud_event.data["message"]["data"]).decode('utf-8'))
    #print(msg_json)
    result = process_email()
    print(result)
    return "success"

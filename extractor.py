import re
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode
import whois
from datetime import datetime
import tldextract

class FeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(self.url).netloc
        self.path = urlparse(self.url).path
        self.soup = None
        self.whois_response = None
        self.response = None
        
        # Try to get the HTML content
        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        # Try to get WHOIS data
        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

    def extract_all(self):
        return {
            'having_IP_Address': self.having_IP_Address(),
            'URL_Length': self.URL_Length(),
            'Shortining_Service': self.Shortining_Service(),
            'having_At_Symbol': self.having_At_Symbol(),
            'double_slash_redirecting': self.double_slash_redirecting(),
            'Prefix_Suffix': self.Prefix_Suffix(),
            'having_Sub_Domain': self.having_Sub_Domain(),
            'SSLfinal_State': self.SSLfinal_State(),
            'Domain_registeration_length': self.Domain_registeration_length(),
            'Favicon': self.Favicon(),
            'port': self.port(),
            'HTTPS_token': self.HTTPS_token(),
            'Request_URL': self.Request_URL(),
            'URL_of_Anchor': self.URL_of_Anchor(),
            'Links_in_tags': self.Links_in_tags(),
            'SFH': self.SFH(),
            'Submitting_to_email': self.Submitting_to_email(),
            'Abnormal_URL': self.Abnormal_URL(),
            'Redirect': self.Redirect(),
            'on_mouseover': self.on_mouseover(),
            'RightClick': self.RightClick(),
            'popUpWidnow': self.popUpWidnow(),
            'Iframe': self.Iframe(),
            'age_of_domain': self.age_of_domain(),
            'DNSRecord': self.DNSRecord(),
            'web_traffic': self.web_traffic(),
            'Page_Rank': self.Page_Rank(),
            'Google_Index': self.Google_Index(),
            'Links_pointing_to_page': self.Links_pointing_to_page(),
            'Statistical_report': self.Statistical_report()
        }

    # 1. having_IP_Address
    def having_IP_Address(self):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
        if match:
            return -1
        else:
            return 1

    # 2. URL_Length
    def URL_Length(self):
        if len(self.url) < 54:
            return 1
        elif len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        else:
            return -1

    # 3. Shortining_Service
    def Shortining_Service(self):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          r'tr\.im|link\.zip\.net',
                          self.url)
        if match:
            return -1
        else:
            return 1

    # 4. having_At_Symbol
    def having_At_Symbol(self):
        if "@" in self.url:
            return -1
        return 1

    # 5. double_slash_redirecting
    def double_slash_redirecting(self):
        list = [x.start(0) for x in re.finditer('//', self.url)]
        if list[len(list)-1] > 6:
            return -1
        else:
            return 1

    # 6. Prefix_Suffix
    def Prefix_Suffix(self):
        if '-' in self.domain:
            return -1
        else:
            return 1

    # 7. having_Sub_Domain
    def having_Sub_Domain(self):
        ext = tldextract.extract(self.url)
        subdomain = ext.subdomain
        if not subdomain:
            return 1
        elif subdomain.count('.') == 0:
            return 0
        else:
            return -1

    # 8. SSLfinal_State
    def SSLfinal_State(self):
        if self.url.startswith("https"):
            return 1
        else:
            return -1

    # 9. Domain_registeration_length
    def Domain_registeration_length(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date - creation_date).days
            if age >= 365:
                return 1
            else:
                return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        if self.soup:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer(r'\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        return 1

    # 11. port
    def port(self):
        try:
            port = self.domain.split(":")[1]
            if port:
                return -1
            else:
                return 1
        except:
            return 1

    # 12. HTTPS_token
    def HTTPS_token(self):
        if re.findall(r"^https\-", self.domain):
            return -1
        else:
            return 1

    # 13. Request_URL
    def Request_URL(self):
        i = 0
        success = 0
        if self.soup:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 1
        return 1

    # 14. URL_of_Anchor
    def URL_of_Anchor(self):
        percentage = 0
        i = 0
        unsafe = 0
        if self.soup:
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1
            try:
                percentage = unsafe / float(i) * 100
            except:
                return 1
            if percentage < 31.0:
                return 1
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                return 0
            else:
                return -1
        return 1

    # 15. Links_in_tags
    def Links_in_tags(self):
        i = 0
        success = 0
        if self.soup:
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer(r'\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1
            try:
                percentage = success / float(i) * 100
            except:
                return 1

            if percentage < 17.0:
                return 1
            elif((percentage >= 17.0) and (percentage < 81.0)):
                return 0
            else:
                return -1
        return 1

    # 16. SFH
    def SFH(self):
        if self.soup:
            for form in self.soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif self.url not in form['action'] and self.domain not in form['action']:
                    return 0
                else:
                    return 1
        return 1

    # 17. Submitting_to_email
    def Submitting_to_email(self):
        if self.response:
            if re.findall(r"[mail\(\)|mailto:?]", self.response.text):
                return -1
            else:
                return 1
        return 1

    # 18. Abnormal_URL
    def Abnormal_URL(self):
        if self.response:
            if self.response.text == "":
                return 1
            if self.whois_response and isinstance(self.whois_response, dict):
                # Using a safe check for hostname in WHOIS
                if str(self.whois_response).lower().find(self.domain.lower()) == -1:
                    return -1
            return 1
        return 1

    # 19. Redirect
    def Redirect(self):
        if self.response:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        return 1

    # 20. on_mouseover
    def on_mouseover(self):
        if self.response:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return -1
            else:
                return 1
        return 1

    # 21. RightClick
    def RightClick(self):
        if self.response:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return -1
            else:
                return 1
        return 1

    # 22. popUpWidnow
    def popUpWidnow(self):
        if self.response:
            if re.findall(r"alert\(", self.response.text):
                return 1
        return 1

    # 23. Iframe
    def Iframe(self):
        if self.response:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return -1
            else:
                return 1
        return 1

    # 24. age_of_domain
    def age_of_domain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today = datetime.now()
            age = (today - creation_date).days
            if age >= 180:
                return 1
            else:
                return -1
        except:
            return -1

    # 25. DNSRecord
    def DNSRecord(self):
        if not self.whois_response:
            return -1
        return 1

    # 26. web_traffic
    def web_traffic(self):
        return 1 # Fallback to 1

    # 27. Page_Rank
    def Page_Rank(self):
        return 1 # Fallback

    # 28. Google_Index
    def Google_Index(self):
        return 1 # Fallback

    # 29. Links_pointing_to_page
    def Links_pointing_to_page(self):
        return 1 # Fallback

    # 30. Statistical_report
    def Statistical_report(self):
        return 1 # Fallback

def extract_features(url):
    extractor = FeatureExtractor(url)
    return extractor.extract_all()

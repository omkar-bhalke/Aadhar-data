


import sys  
import requests  
import base64  
import hashlib  
from bs4 import BeautifulSoup  
import re  
import pytesseract  
from PIL import Image  
import io  
  
class IMPDSAutomation:  
    def __init__(self):  
        self.session = requests.Session()  
        self.base_url = "https://impds.nic.in/impdsdeduplication"  
        self.user_salt = None  
        self.csrf_token = None  



          
        self.session.headers.update({  
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',  
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',  
            'Accept-Language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',  
            'Connection': 'keep-alive',  
        })  



  
    def sha512(self, text):  
        return hashlib.sha512(text.encode('utf-8')).hexdigest()  
  
    def get_login_page(self):  
        url = f"{self.base_url}/LoginPage"  
        response = self.session.get(url)  
        if response.status_code == 200:  
            soup = BeautifulSoup(response.text, 'html.parser')  
            csrf_input = soup.find('input', {'name': 'REQ_CSRF_TOKEN'})  
            if csrf_input:  
                self.csrf_token = csrf_input.get('value')  
                print(f"[+] CSRF Token: {self.csrf_token}")  



  
            for script in soup.find_all('script'):  
                if script.string and 'USER_SALT' in script.string:  
                    match = re.search(r"USER_SALT\s*=\s*'([^']+)'", script.string)  
                    if match:  
                        self.user_salt = match.group(1)  
                        print(f"[+] User Salt: {self.user_salt}")  
            return True  
        print("[-] Failed to load login page")  
        return False  



  
    def get_captcha(self):  
        url = f"{self.base_url}/ReloadCaptcha"  
        response = self.session.post(url)  
        if response.status_code == 200:  
            try:  
                data = response.json()  
                return data.get('captchaBase64')  
            except Exception:  
                return None  
        return None  



  
    def solve_captcha_auto(self, captcha_base64):  
        try:  
            image_data = base64.b64decode(captcha_base64)  
            image = Image.open(io.BytesIO(image_data))  
            image = image.convert('L')  # grayscale for better OCR  
            text = pytesseract.image_to_string(image, config="--psm 7").strip()  
            clean_text = ''.join(filter(str.isalnum, text.upper()))  
            print(f"[+] OCR Captcha Read: {clean_text}")  
            return clean_text  
        except Exception as e:  
            print("[-] OCR failed:", e)  
            return None  



  
    def save_captcha_image(self, captcha_base64, filename="captcha.png"):  
        if captcha_base64:  
            image_data = base64.b64decode(captcha_base64)  
            with open(filename, 'wb') as f:  
                f.write(image_data)  
            print(f"[+] CAPTCHA saved as {filename}")  
            return filename  
        return None  



  
    def login(self, captcha_text):  
        if not self.csrf_token or not self.user_salt:  
            print("[-] Call get_login_page() first.")  
            return False  
  
        username = "dsojpnagar@gmail.com"  
        password = "CHCAEsoK"  



  
        salted_password = self.sha512(self.sha512(self.user_salt) + self.sha512(password))  
  
        data = {  
            'userName': username,  
            'password': salted_password,  
            'captcha': captcha_text,  
            'REQ_CSRF_TOKEN': self.csrf_token  
        }  
  
        response = self.session.post(f"{self.base_url}/UserLogin", data=data)  
  
        if response.status_code == 200:  
            try:  
                result = response.json()  
            except Exception:  
                print("[-] Non-JSON response")  
                return False  
  
            if result.get('athenticationError'):  
                print("[-] Login failed! Possibly wrong captcha.")  
                return False  
            else:  
                print("[+] Login successful!")  
                jsessionid = self.session.cookies.get('JSESSIONID')  
                if jsessionid:  
                    print(f"[+] JSESSIONID: {jsessionid}")  
                    with open("session.txt", "w") as f:  
                        f.write(jsessionid)  
                    print("[+] Saved JSESSIONID to session.txt")  
                    return jsessionid  
                else:  
                    print("[-] JSESSIONID not found")  
                    return True  
        else:  
            print(f"[-] Login failed, HTTP {response.status_code}")  
            return False  
  
  
def main():  
    automator = IMPDSAutomation()  
  
    if not automator.get_login_page():  
        return  
  
    captcha_base64 = automator.get_captcha()  
    if not captcha_base64:  
        print("[-] CAPTCHA fetch failed.")  
        return  
  
    captcha_text = automator.solve_captcha_auto(captcha_base64)  
    automator.save_captcha_image(captcha_base64)  

    if not captcha_text:  
        # Running on a server with no TTY — never block on input(), just fail this attempt.  
        # The Node wrapper will retry automatically on the next call.  
        print("[-] OCR failed to read CAPTCHA and no interactive input is available. Aborting this attempt.")  
        sys.exit(1)  
  
    jsessionid = automator.login(captcha_text)  
    if jsessionid:  
        print(f"\n✅ Final JSESSIONID: {jsessionid}")  
        sys.exit(0)  
    else:  
        print("[-] Login unsuccessful.")  
        sys.exit(1)  
  
  
if __name__ == "__main__":  
    try:  
        main()  
    except Exception as e:  
        print(f"[-] Unexpected error: {e}")  
        sys.exit(1)  






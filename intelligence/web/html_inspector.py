import requests
from bs4 import BeautifulSoup

def detect_login_form(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")
        for form in forms:
            password_inputs = form.find_all("input", {"type": "password"})
            if password_inputs:
                return {
                    "url": url,
                    "login_form_detected": True,
                    "reason": "Password input field found"
                }

        return {
            "url": url,
            "login_form_detected": False
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }

if __name__ == "__main__":
    test_urls = [
        "https://accounts.google.com",
        "https://example.com"
    ]

    for u in test_urls:
        print(detect_login_form(u))
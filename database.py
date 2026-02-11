# База "тел" серверов (без знака # и названия)
SERVER_TEMPLATES = {
    "LTE1_EU": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@146.185.243.18:5444?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "LTE1_RU": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@146.185.243.18:443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "LTE2_EU": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@37.139.32.238:5444?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "LTE2_RU": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@37.139.32.238:443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "LTE3_EU": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@5.188.142.120:5444?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "LTE3_RU": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@5.188.142.120:5443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "LTE4_EU": "",
    "LTE4_RU": "",
    "SIGN": "vless://perez@127.0.0.1:443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=qq&sni=www.vk.com&pbk=just-a-sign",
    "LTE185_XHTTP": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@185.71.67.79:443?flow=&type=xhttp&host=api.kittystars.ru&path=/&mode=auto&security=tls&sni=api.kittystars.ru&alpn=h2,http/1.1&fp=chrome&allowInsecure=0",
    "LTE185_WS": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@185.71.67.79:443?flow=&type=ws&host=legacy.kittystars.ru&path=/ws&security=tls&sni=legacy.kittystars.ru&fp=chrome&allowInsecure=0",
    "T2_1": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@217.13.104.101:3443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=qq&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "T2_2": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@217.13.111.70:3443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=max.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "Poland": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@91.211.27.167:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=google.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "Germany": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@109.248.168.18:8443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=eurofurence.org&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "NL_1": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@213.109.147.50:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=google.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "NL_3": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@144.31.30.69:443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=eh.vk.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "Hungary": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@217.13.104.204:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=api-maps.yandex.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "Czech": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@45.151.183.175:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=google.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "Moscow_1": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@89.221.203.3:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=ie.ozone.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "Moscow_2": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@84.252.100.168:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=qq&sni=ie.ozone.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "SPB": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@188.225.77.238:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=qq&sni=ie.ozone.ru&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
    "USA": "vless://7bee7ce0-f4c1-4d12-bdc0-a1c8c8e6f30f@151.241.100.151:2443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=chrome&sni=google.com&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2",
    "Germany_Plus": "vless://9d365a6d-4b01-4932-a0c1-86a2e873a4c1@s2.nodu6.ru:8443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=qq&sni=www.vk.com&pbk=CsuH3tuUBGh5oMxWos7EUvO-qMOeCuDcVcVeEtKRYnI",
    "Poland_Plus": "vless://9d365a6d-4b01-4932-a0c1-86a2e873a4c1@pol2.linkey37.ru:443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=edge&sni=www.yandex.ru&pbk=QRvZBf0tz7ij9V7L4MjXkHoMkdDAbwc-UzyDt-PLshU",
    "NL_2": "vless://9d365a6d-4b01-4932-a0c1-86a2e873a4c1@s1.nodu3.ru:443?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality&fp=qq&sni=www.vk.com&pbk=dR3W06Hm_v5LOrWtoTt6IZxpmQwugXhE7m3xNU7JW30",
    "LTE5_RU": "",
    
    
    
    
    
    
}

# Настройки подписок: (ID сервера, Кастомное имя)
SUBSCRIPTIONS = {
    "beeline_test.txt": [
        ("LTE1_EU", "🇪🇺🔵Билайн №1"),
        ("LTE1_RU", "🇷🇺🔵Билайн №2"),
        ("LTE2_EU", "🇪🇺⚪Билайн №3"),
        ("LTE2_RU", "🇷🇺⚪Билайн №4"),
        ("LTE3_EU", "🇪🇺🟣Билайн №5"),
        ("LTE3_RU", "🇷🇺🟣Билайн №6"),
        ("Germany_Plus", "🇩🇪🛜Германия Wi-Fi"),
    ],
    "megafon_users.txt": [
        ("srv_37_139_5444", "🚀 МегаФон Ультра"),
        ("srv_146_185_5444", "⚡️ МегаФон Лайт"),
    ],
    "mixed_user.txt": [
        ("srv_37_139_5444", "Default Server"),
        ("srv_37_139_443", "Backup Server"),
    ]
}
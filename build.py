import urllib.parse
import base64
import json
import re
import os
from database import SERVER_TEMPLATES, SUBSCRIPTIONS

def parse_vless(line):
    """Парсит VLESS ссылку в словарь параметров для Clash."""
    line = line.strip()
    if not line.startswith('vless://'):
        return None
        
    line = line[8:]
    is_shadowrocket = False
    
    # Регулярка для стандарта: uuid@server:port?query#name
    match = re.match(r'^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$', line)
    
    if not match:
        # Попытка распарсить формат Shadowrocket (base64 часть до параметров)
        b64_match = re.match(r'^(.*?)(\?.*?)$', line)
        if b64_match:
            b64_part, other = b64_match.groups()
            b64_part += '=' * (-len(b64_part) % 4)
            try:
                decoded = base64.urlsafe_b64decode(b64_part).decode('utf-8')
                line = decoded + other
                match = re.match(r'^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$', line)
                is_shadowrocket = True
            except:
                pass
                
    if not match:
        return None
        
    uuid, server, port_str, _, addons, name = match.groups()
    
    # Очистка UUID от возможных вкраплений Shadowrocket (user:pass)
    if is_shadowrocket and ':' in uuid:
        uuid = uuid.split(':')[-1]
        
    port = int(port_str)
    uuid = urllib.parse.unquote(uuid)
    name = urllib.parse.unquote(name or '').strip()
    
    proxy = {
        'name': name or f"VLESS_{server}_{port}",
        'server': server,
        'port': port,
        'uuid': uuid,
        'udp': True,
        'network': 'tcp'
    }
    
    params = dict(urllib.parse.parse_qsl(addons or ""))
    
    # TLS и Безопасность
    sec = params.get('security', '').lower()
    if sec and sec != 'none':
        proxy['tls'] = True
        
    # Специфика Shadowrocket TLS
    if is_shadowrocket and params.get('tls', '').upper() in ('TRUE', '1'):
        proxy['tls'] = True
        sec = sec or "reality"
        
    sni = params.get('sni') or params.get('peer')
    if sni: proxy['servername'] = sni
    
    if params.get('flow'): proxy['flow'] = 'xtls-rprx-vision'
    if params.get('allowInsecure', '').upper() in ('TRUE', '1'): proxy['skip-cert-verify'] = True
    if params.get('fp'): proxy['client-fingerprint'] = params.get('fp')
    if params.get('alpn'): proxy['alpn'] = params['alpn'].replace('%2F', '/').split(',')
        
    # Reality
    if sec == 'reality':
        proxy['reality-opts'] = {}
        if params.get('pbk'): proxy['reality-opts']['public-key'] = params.get('pbk')
        if params.get('sid'): proxy['reality-opts']['short-id'] = params.get('sid')
        
    # Транспорт (Network)
    net_type = params.get('type', 'tcp').lower()
    if net_type == 'httpupgrade':
        proxy['network'] = 'ws'
        proxy['ws-opts'] = {'v2ray-http-upgrade': True}
    else:
        proxy['network'] = net_type if net_type in ('tcp', 'ws', 'http', 'grpc', 'h2') else 'tcp'
        
    if proxy['network'] == 'ws':
        proxy.setdefault('ws-opts', {})
        if params.get('path'): proxy['ws-opts']['path'] = urllib.parse.unquote(params['path'])
        host = params.get('host') or params.get('obfsParam')
        if host:
            try:
                headers = json.loads(host)
                if headers: proxy['ws-opts']['headers'] = headers
            except:
                proxy['ws-opts']['headers'] = {'Host': host}
                
    elif proxy['network'] == 'grpc':
        if params.get('serviceName'):
            proxy['grpc-opts'] = {'grpc-service-name': urllib.parse.unquote(params['serviceName'])}
            
    return proxy

def generate_clash_yaml(uris):
    """Формирует полный текст YAML конфига."""
    proxies = []
    for uri in uris:
        p = parse_vless(uri)
        if p: proxies.append(p)
            
    if not proxies: return ""

    lines = ["proxies:"]
    proxy_names = []
    
    for p in proxies:
        safe_name = p['name'].replace('"', '\\"')
        proxy_names.append(safe_name)
        
        lines.append(f"  - name: \"{safe_name}\"")
        lines.append(f"    type: vless")
        lines.append(f"    server: {p['server']}")
        lines.append(f"    port: {p['port']}")
        lines.append(f"    uuid: {p['uuid']}")
        if p.get('udp'): lines.append("    udp: true")
        if p.get('tls'): lines.append("    tls: true")
        if p.get('servername'): lines.append(f"    servername: {p['servername']}")
        if p.get('flow'): lines.append(f"    flow: {p['flow']}")
        if p.get('skip-cert-verify'): lines.append("    skip-cert-verify: true")
        if p.get('client-fingerprint'): lines.append(f"    client-fingerprint: {p['client-fingerprint']}")
        if p.get('alpn'): lines.append(f"    alpn: {json.dumps(p['alpn'])}")
        if p.get('network') != 'tcp': lines.append(f"    network: {p['network']}")
            
        if p.get('reality-opts'):
            lines.append("    reality-opts:")
            lines.append(f"      public-key: {p['reality-opts'].get('public-key', '')}")
            if 'short-id' in p['reality-opts']: lines.append(f"      short-id: {p['reality-opts']['short-id']}")
                
        if p['network'] == 'ws' and p.get('ws-opts'):
            lines.append("    ws-opts:")
            if 'path' in p['ws-opts']: lines.append(f"      path: {p['ws-opts']['path']}")
            if 'headers' in p['ws-opts']:
                lines.append("      headers:")
                for k, v in p['ws-opts']['headers'].items(): lines.append(f"        {k}: {v}")
            if p['ws-opts'].get('v2ray-http-upgrade'): lines.append("      v2ray-http-upgrade: true")
                
        if p['network'] == 'grpc' and p.get('grpc-opts'):
            lines.append("    grpc-opts:")
            lines.append(f"      grpc-service-name: {p['grpc-opts']['grpc-service-name']}")
            
    # Добавляем обязательные группы и правила
    lines.append("\nproxy-groups:")
    lines.append("  - name: VPN")
    lines.append("    type: select")
    lines.append("    proxies:")
    for name in proxy_names:
        lines.append(f"      - \"{name}\"")
        
    lines.append("\nrules:")
    lines.append("  - MATCH,VPN")
    
    return "\n".join(lines)

def build():
    for filename, data in SUBSCRIPTIONS.items():
        # Определяем режим работы (список или словарь с настройками)
        is_clash_enabled = False
        server_list = []

        if isinstance(data, dict):
            server_list = data.get("servers", [])
            is_clash_enabled = data.get("clash", False)
        else:
            server_list = data

        ready_links = []
        for server_id, custom_name in server_list:
            if server_id in SERVER_TEMPLATES:
                base_link = SERVER_TEMPLATES[server_id]
                encoded_name = urllib.parse.quote(custom_name)
                # Если в шаблоне уже есть #, заменяем его
                if "#" in base_link:
                    full_link = base_link.split("#")[0] + "#" + encoded_name
                else:
                    full_link = f"{base_link}#{encoded_name}"
                ready_links.append(full_link)
        
        if not ready_links:
            continue

        # Сохраняем стандартный TXT
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(ready_links))
        print(f"[TXT] {filename} собран.")
        
        # Сохраняем YAML, если активирован флаг clash
        if is_clash_enabled:
            yaml_filename = filename.rsplit('.', 1)[0] + ".yaml"
            yaml_content = generate_clash_yaml(ready_links)
            if yaml_content:
                with open(yaml_filename, "w", encoding="utf-8") as f:
                    f.write(yaml_content)
                print(f"[YAML] {yaml_filename} создан.")

if __name__ == "__main__":
    build()

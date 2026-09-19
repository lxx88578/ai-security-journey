import os
import requests

API_KEY = os.environ.get("DEEPSEEK_API_KEY")
if not API_KEY:
    print("错误：环境变量 DEEPSEEK_API_KEY 没有设置")
    print('请先执行：export DEEPSEEK_API_KEY="sk-你的密钥"')
    exit(1)

url = "https://api.deepseek.com/chat/completions"
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}
data = {
    "model": "deepseek-chat",
    "messages": [
        {"role": "system", "content": "你是一位网络安全专家，用简洁的中文回答。"},
        {"role": "user", "content": "我对 SQL 注入的理解是：攻击者在输入框里填 ' or 1=1 就能绕过登录。请指出哪里错了、遗漏了什么。"},
    ],
    "temperature": 0.7,
}

resp = requests.post(url, headers=headers, json=data, timeout=60)
resp.raise_for_status()
print(resp.json()["choices"][0]["message"]["content"])

"""故意包含多种安全问题和质量问题的测试代码，用于演示扫描效果。"""

import os
import pickle
import hashlib
import random
import sqlite3

# ===== 硬编码敏感信息 =====
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "admin123"
SECRET_TOKEN = "ghp_ABCDEFGHIJKLMNOPqrstuvwxyz123456"


# ===== SQL 注入 =====
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


# ===== 不安全的反序列化 =====
def load_user_data(data_bytes):
    return pickle.loads(data_bytes)


# ===== eval/exec 注入 =====
def calculate(expression):
    return eval(expression)


# ===== 不安全的随机数（用于安全场景） =====
def generate_token():
    return str(random.randint(100000, 999999))


# ===== 裸 except =====
def risky_operation():
    try:
        result = 1 / 0
        return result
    except:
        return None


# ===== 过度复杂的函数 =====
def process_order(order_type, amount, customer_level, region, promo_code, payment_method):
    if order_type == "normal":
        if amount > 1000:
            if customer_level == "vip":
                if region == "domestic":
                    if promo_code:
                        if payment_method == "alipay":
                            return amount * 0.7
                        elif payment_method == "wechat":
                            return amount * 0.72
                        else:
                            return amount * 0.75
                    else:
                        return amount * 0.8
                elif region == "international":
                    return amount * 0.85
                else:
                    return amount * 0.9
            elif customer_level == "regular":
                if region == "domestic":
                    return amount * 0.9
                else:
                    return amount * 0.95
            else:
                return amount
        elif amount > 500:
            if customer_level == "vip":
                return amount * 0.85
            else:
                return amount * 0.95
        else:
            return amount
    elif order_type == "return":
        if amount > 500:
            return -amount * 0.5
        else:
            return -amount
    elif order_type == "exchange":
        if customer_level == "vip":
            return 0
        else:
            return amount * 0.1
    else:
        return None


# ===== 弱哈希 =====
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# ===== 命令注入 =====
def ping_host(hostname):
    import subprocess
    return subprocess.call("ping -c 1 " + hostname, shell=True)

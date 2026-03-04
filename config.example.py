import os
from dotenv import load_dotenv

load_dotenv()

# ใส่ API Key ใน .env เท่านั้น (ห้ามใส่ตรงนี้)
API_KEY = os.getenv("fe008837a4b536f86b53bdfc0a88d8768adfd498")

backup_tag = ''
restore_tag = 'merakiRestore'
backup_directory = './backup'

org_number_filter = ['898102']
org_name_filter = ''

logging_level = "DEBUG"
console_logging = True
max_retries = 100
max_requests = 10

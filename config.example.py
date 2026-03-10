import os
from dotenv import load_dotenv

load_dotenv()

# ใส่ API Key ใน .env เท่านั้น (ห้ามใส่ตรงนี้)
API_KEY = os.getenv("fe008837a4b536f86b53bdfc0a88d8768adfd498")

backup_tag = ''
restore_tag = 'merakiRestore'
backup_directory = './backup'
log_directory = './logs'
auto_backup_settings_file = './auto_backup_settings.json'
auto_backup_task_name = 'MerakiBackupAuto'

org_number_filter = ['898102']
org_name_filter = ''

logging_level = "DEBUG"
console_logging = True
max_retries = 100
max_requests = 10

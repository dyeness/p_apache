import re
import os
import pandas as pd
import matplotlib.pyplot as plt

# Шаблони для виявлення атак
xss_patterns = ['%3C', '<img', '<a href', '<body', '<script', '<b', '<h', '<marquee']
sqli_patterns = ['%27', '--', '%3B', 'exec', 'union+', 'union*', 'system(', 'eval(', 'group_concat', 'column_name', 'order by', 'insert into', '@version']
idor_patterns = ['../', '%2e%2f', '%2e%2e/', '.%2f', '..%c1%9', '..%c0%af', '/usr/', '/passwd', '/grub', 'boot.ini', '/conf/', '/etc/', '/proc/', '/opt/', '/sbin/', '/dev/', '/tmp/', '/kern/', '/root/', '/sys/', '/system/', '/windows/', '/winnt/', '/inetpub/', '/localstart/', '/boot/']

# Функція для парсингу логів
def parse_logs(file_path):
    data = []
    xss_attempts = 0
    sqli_attempts = 0
    idor_attempts = 0
    
    with open(file_path, 'r') as file:
        for line in file:
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            url_match = re.search(r'\"[A-Z]+\s(.*?)\sHTTP', line)
            
            if ip_match and url_match:
                ip = ip_match.group(1)
                url = url_match.group(1)
                
                # Перевірка на XSS, SQL ін'єкції та IDOR
                if any(pattern in url for pattern in xss_patterns):
                    xss_attempts += 1
                if any(pattern in url for pattern in sqli_patterns):
                    sqli_attempts += 1
                if any(pattern in url for pattern in idor_patterns):
                    idor_attempts += 1
                
                data.append({'IP': ip, 'URL': url})
    
    return pd.DataFrame(data), xss_attempts, sqli_attempts, idor_attempts

# Функція для аналізу всіх .log файлів у вказаній директорії
def analyze_all_logs_in_directory(directory_path):
    all_data = []
    total_xss_attempts = 0
    total_sqli_attempts = 0
    total_idor_attempts = 0

    # Проходимо через всі файли в директорії
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        
        # Перевіряємо, чи файл є логом (перевірка на розширення .log)
        if os.path.isfile(file_path) and filename.endswith('.log'):
            print(f"Processing file: {filename}")
            
            # Використовуємо parse_logs для обробки кожного файлу
            data_frame, xss_attempts, sqli_attempts, idor_attempts = parse_logs(file_path)
            
            # Додаємо результати до загальної статистики
            all_data.append(data_frame)
            total_xss_attempts += xss_attempts
            total_sqli_attempts += sqli_attempts
            total_idor_attempts += idor_attempts

    # Об'єднуємо всі дані в один DataFrame
    combined_data = pd.concat(all_data, ignore_index=True)
    
    # Групування та сортування за IP-адресою та URL
    ip_url_counts = combined_data.groupby(['IP', 'URL']).size().reset_index(name='Count')
    ip_url_counts = ip_url_counts.sort_values(by='Count', ascending=False)

    # Зберігаємо повний звіт у CSV
    ip_url_counts.to_csv('top_ip_url_full.csv', index=False, sep='\t')
    ip_url_counts.head(10).to_csv('top_ip_url_10.csv', index=False, sep='\t')
    ip_url_counts.head(100).to_csv('top_ip_url_100.csv', index=False, sep='\t')

    # Відображення топ-10 IP на графіку
    ip_url_counts.head(10).plot(kind='barh', x='IP', y='Count', title='Top 10 IPs by Request Count')
    plt.xlabel('Number of Requests')
    plt.ylabel('IP Addresses')
    plt.gca().invert_yaxis()
    plt.show()

    # Виведення статистики атак
    print(f"Загальна кількість XSS атак: {total_xss_attempts}")
    print(f"Загальна кількість SQL ін'єкцій: {total_sqli_attempts}")
    print(f"Загальна кількість IDOR атак: {total_idor_attempts}")

# Виклик функції для аналізу всіх файлів у вказаній директорії
directory_path = './'  # Вкажіть шлях до директорії з файлами логів
analyze_all_logs_in_directory(directory_path)

import re
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

# Основний код
file_path = './access.log' #! Шлях до файлу з логами (можна вказати шлях через папки)
data_frame, xss_attempts, sqli_attempts, idor_attempts = parse_logs(file_path)

# Групування та сортування за комбінацією IP-адреси і URL-адреси
ip_url_counts = data_frame.groupby(['IP', 'URL']).size().reset_index(name='Count')
ip_url_counts = ip_url_counts.sort_values(by='Count', ascending=False)

# Збереження у CSV з роздільником з одного табулятора
ip_url_counts.to_csv('top_ip_url_full.csv', index=False, sep='\t')
ip_url_counts.head(10).to_csv('top_ip_url_10.csv', index=False, sep='\t')
ip_url_counts.head(100).to_csv('top_ip_url_100.csv', index=False, sep='\t')

# Відображення топ-10 комбінацій IP та URL за кількістю запитів, показуючи IP-адреси на графіку
ip_url_counts.head(10).plot(kind='barh', x='IP', y='Count', title='Top 10 IPs by Request Count')
plt.xlabel('Number of Requests')
plt.ylabel('IP Addresses')
plt.gca().invert_yaxis()
plt.show()

# Виведення статистики атак
print(f"Кількість XSS атак: {xss_attempts}")
print(f"Кількість SQL ін'єкцій: {sqli_attempts}")
print(f"Кількість IDOR атак: {idor_attempts}")

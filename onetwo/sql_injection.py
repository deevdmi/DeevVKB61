import threading
import paramiko
import os
from tkinter import *
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re

exceptions_users = ['Users:']
exceptions_ip = ['IP:']
exceptions_queries = ['Queries:']

# Функция сохранения настроек
def save_to_file():
    # Получение значений из полей ввода
    field1_value = entry31.get().strip()
    field11_value = entry311.get().strip()
    field2_value = entry32.get().strip()
    field3_value = entry33.get().strip()
    field4_value = entry34.get().strip()
    field5_value = entry35.get().strip()
    field6_value = entry36.get().strip()
    field7_value = entry37.get().strip()
    file_name = "settings.txt"

    if not field7_value:
        field7_value = "10"

    # Получение значений из всех полей ввода
    field_values = [field1_value, field11_value, field2_value, field3_value, field4_value, field5_value, field6_value]

    # Проверка на пустые поля
    if any(not value for value in field_values):  # Если хоть одно поле пустое
        messagebox.showerror("Ошибка", "Одно из полей не заполнено!")
        return

    try:
        # Открытие файла в режиме записи (создаст файл, если его нет)
        with open(file_name, "w") as file:
            file.write(f"server:{field1_value}\n")
            file.write(f"port:{field11_value}\n")
            file.write(f"login:{field2_value}\n")
            file.write(f"password:{field3_value}\n")
            file.write(f"email:{field4_value}\n")
            file.write(f"telegram:{field5_value}\n")
            file.write(f"path_to_logs:{field6_value}\n")
            file.write(f"auto_block:{field7_value}\n")
        messagebox.showinfo("Успех", f"Данные сохранены в файл '{file_name}'.")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

    # Очистка полей ввода
    entry31.delete(0, tk.END)
    entry311.delete(0, tk.END)
    entry32.delete(0, tk.END)
    entry33.delete(0, tk.END)
    entry34.delete(0, tk.END)
    entry35.delete(0, tk.END)
    entry36.delete(0, tk.END)
    entry37.delete(0, tk.END)

# Функция добавления исключений
def save_exceptions():

    user = entry38.get().strip()
    ip = entry39.get().strip()
    query = entry40.get().strip()

    # Проверка, что хотя бы одно поле заполнено
    if not user and not ip and not query:
        messagebox.showerror("Ошибка", "Все поля пустые!")
        return

    try:
        # Читаем существующий файл
        with open("exceptions.txt", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        # Если файл отсутствует, создаём его с начальным содержимым
        lines = ["Users:\n", "IP:\n", "Queries:\n"]
        with open("exceptions.txt", "w") as file:  # Открываем файл для записи (создаётся новый файл)
            file.writelines(lines)  # Записываем начальные строки в файл

    # Обновляем строки
    updated_lines = []
    for line in lines:
        if line.startswith("Users:"):
            current_value = line[len("Users:"):].strip()
            new_value = user
            if new_value:
                if current_value:
                    updated_lines.append(f"Users: {new_value}, {current_value}\n")
                else:
                    updated_lines.append(f"Users: {new_value}\n")
            else:
                updated_lines.append(line)
        elif line.startswith("IP:"):
            current_value = line[len("IP:"):].strip()
            new_value = ip
            if new_value:
                if current_value:
                    updated_lines.append(f"IP: {new_value}, {current_value}\n")
                else:
                    updated_lines.append(f"IP: {new_value}\n")
            else:
                updated_lines.append(line)
        elif line.startswith("Queries:"):
            current_value = line[len("Queries:"):].strip()
            new_value = query
            if new_value:
                if current_value:
                    updated_lines.append(f"Queries: {new_value}, {current_value}\n")
                else:
                    updated_lines.append(f"Queries: {new_value}\n")
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)
    messagebox.showinfo("Успех", "Данные сохранены в файл exceptions.txt")
    # Запись обновленного содержимого в файл
    with open("exceptions.txt", "w") as file:
        file.writelines(updated_lines)


    # Очистка полей ввода
    entry38.delete(0, tk.END)
    entry39.delete(0, tk.END)
    entry40.delete(0, tk.END)


def show_exceptions():
    file_path = "exceptions.txt"

    os.startfile(file_path)  # Открытие файла с помощью стандартной ассоциации

def go_ssh_func():
    # Путь к вашему файлу
    file_settings = 'settings.txt'

    # Словарь для хранения данных
    config = {}

    # Чтение файла
    with open(file_settings, 'r') as file:
        for line in file:
            if ':' in line:
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip()

    # Присвоение значений переменным
    host = config.get('server')
    port = config.get('port')
    username = config.get('login')
    password = config.get('password')
    email = config.get('email')
    telegram = config.get('telegram')
    path_to_logs = config.get('path_to_logs')
    auto_block = config.get('auto_block')

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Автоматически добавляем ключи хоста

    try:
        # Подключаемся к хосту
        ssh_client.connect(hostname=host, port=port, username=username, password=password)
        print(f"Подключено к {host}")

        lb1 = Label(tab1, text="установлено", font=("Arial", 14, "bold"), fg='green')
        lb1.place(x=300, y=20)

        lb222 = Label(tab1, text="активно", font=("Arial", 14, "bold"), fg='green')
        lb222.place(x=300, y=120)

        lb333 = Label(tab1, text="активно", font=("Arial", 14, "bold"), fg='green')
        lb333.place(x=270, y=220)

        #grep 'cpu ' / proc / stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage "%"}'

        #Открываем удалённый файл через команду tail
        command = f"tail -f {path_to_logs}"  # Чтение файла в режиме реального времени
        stdin, stdout, stderr = ssh_client.exec_command(command)

        print(f"Чтение логов из {path_to_logs}...")

        # Паттерны для поиска SQL-инъекций
        sql_injection_patterns = [
            r"(?i)(?:\bor\b|\band\b)\s+['\"]?\d+=\d+['\"]?",  # OR 1=1 или OR '1=1'
            r"(?i)\bunion\b.*\bselect\b",  # UNION SELECT
            r"(?i)\bselect\b.*\bfrom\b.*;--",  # SELECT FROM с комментарием
            r"(?i)'.*--",  # Одинарная кавычка с комментарием
            r"(?i)'.*or.*=.*",  # Одинарная кавычка с условием
            r"(?i)\".*--",  # Двойные кавычки с комментарием
            r";\s*(DROP|INSERT|DELETE|UPDATE)\b",  # Завершение запроса и опасные операторы
            r"(?i)(\bor\b\s*1\s*=\s*1\b)",  # OR 1=1
            r"(?i)(\bunion\b.*\bselect\b)",  # UNION SELECT
            r"(?i)(\bselect\b.*\bfrom\b.*\binformation_schema\b)",  # Обход через information_schema
            r"(?i)(\bupdate\b.*\bset\b.*=.*)",  # Изменение данных через UPDATE
            r"(?i)(\bdelete\b.*\bfrom\b)",  # Удаление через DELETE
            r"(?i)(\binsert\b.*\binto\b)",  # Вставка данных через INSERT
            r"(?i)(\bdrop\b\s+\b(table|database|view|procedure)\b)",  # DROP TABLE и другие DDL-команды
            r"(?i)(\bexec\b.*\bxp_cmdshell\b)",  # Выполнение системных команд
            r"(?i)(\b--\b|\b#\b)",  # SQL комментарии
            r"(?i)(\bbenchmark\b.*\(\d+,\s*md5\()")  # Временные атаки (time-based)
        ]

        # Открытие файла для записи результатов
        output_file = open("suspicious_logs.txt", "w")

        # Паттерн для разбора строки лога
        log_pattern = r"(?P<date>\S+\s\S+)\s(?P<timezone>\S+)\s\[(?P<pid>\d+)\]\s\[(?P<user_id>\d+)\]\s\[(?P<app_id>\d+/\d+)\]:\suser=(?P<user>\S+),db=(?P<database>\S+),app=(?P<app>\S+),client=\[(?P<client_ip>[^\]]+)\].*STATEMENT:\s*(?P<query>.+)"


        #Читаем вывод в реальном времени
        for line in iter(stdout.readline, ""):
            line = line.strip()
            print(line)
            
        if is_excluded(ip, user, query):
        return  # Если запрос в исключениях, ничего не делаем
            
        # Поиск слова 'STATEMENT' в строке
        
            if "STATEMENT" in line:
                print('true')
                # Извлечение самого SQL-запроса
                match = re.search(r"STATEMENT:\s*(.*)", line)
                if match:
                    sql_query = match.group(1)
                    print(sql_query)

                    # Проверка на наличие паттернов SQL-инъекций
                    for pattern in sql_injection_patterns:
                        if re.search(pattern, sql_query):
                            print('ok save')
                            # Сохранение строки в файл
                            output_file.write(line + "\n")
                            output_file.flush()

                            # Разбор строки лога с помощью регулярного выражения
                            log_match = re.match(log_pattern, line)
                            if log_match:
                                log_data = log_match.groupdict()  # Получаем данные в виде словаря

                                # Добавление данных в Treeview
                                tree.insert("", "end", values=(
                                    log_data["date"],
                                    log_data["pid"],
                                    log_data["user"],
                                    log_data["app"],
                                    log_data["database"],
                                    log_data["query"],
                                    log_data["client_ip"]
                                ))

                            break

        # Закрытие файла
        output_file.close()

    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        ssh_client.close()
        print("Соединение закрыто.")

def go_ssh():
    thread = threading.Thread(target=go_ssh_func)
    thread.daemon = True  # Поток завершится при закрытии программы
    thread.start()

# Блок блокирования
def block_ip_iptables(host, username, password, ip_address):
    # Блокировка IP-адреса через iptables.
    ip_address = entry22.get()
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    output, error = ssh_execute(host, username, password, command)
    if error:
        print(f"Ошибка при блокировке IP {ip_address}: {error}")
    else:
        print(f"IP {ip_address} успешно заблокирован.")


def block_db_user(host, username, password, db_user):
    # Блокировка пользователя в PostgreSQL.
    db_user = entry21.get()
    command = f"psql -U postgres -c \"ALTER ROLE {db_user} WITH NOLOGIN;\""
    output, error = ssh_execute(host, username, password, command)
    if error:
        print(f"Ошибка при блокировке пользователя {db_user}: {error}")
    else:
        print(f"Пользователь {db_user} успешно заблокирован.")


def terminate_db_process(host, username, password, pid):
    # Завершение процесса PostgreSQL по PID.
    pid = entry23.get()
    command = f"psql -U postgres -c \"SELECT pg_terminate_backend({pid});\""
    output, error = ssh_execute(host, username, password, command)
    if error:
        print(f"Ошибка при завершении процесса {pid}: {error}")
    else:
        print(f"Процесс {pid} успешно завершён.")

# Автоматическое блокирование
def block_ip_if_needed(host, username, password, ip_address, n):
    # Блокирует IP, если число опасных запросов превышает порог n.
    n = int(entry37.get())
    count = count_dangerous_queries(host, username, password, ip_address, n)
    
    if count > n:
        print(f"Обнаружено {count} опасных запросов с IP {ip_address}. Блокируем...")
        block_ip_iptables(host, username, password, ip_address)
    else:
        print(f"Опасных запросов с {ip_address}: {count}. Блокировка не требуется.")

# Исключения
EXCLUSIONS_FILE = "exclusions.txt"

def load_exclusions():
    """Загружает исключения из файла в три списка: IP-адреса, пользователи и фрагменты запросов."""
    ip_exclusions = entry39.get()
    user_exclusions = entry38.get()
    query_exclusions = entry40.get()
    
    if not os.path.exists(EXCLUSIONS_FILE):
        return ip_exclusions, user_exclusions, query_exclusions

    with open(EXCLUSIONS_FILE, "r") as file:
        for line in file:
            line = line.strip()
            if line.startswith("IP:"):
                ip_exclusions.add(line.replace("IP:", "").strip())
            elif line.startswith("USER:"):
                user_exclusions.add(line.replace("USER:", "").strip())
            elif line.startswith("QUERY:"):
                query_exclusions.add(line.replace("QUERY:", "").strip())

    return ip_exclusions, user_exclusions, query_exclusions

def add_to_exclusions(category, value):
    """Добавляет IP, пользователя или запрос в исключения и сохраняет в файл."""
    if category not in ["IP", "USER", "QUERY"]:
        raise ValueError("Категория должна быть 'IP', 'USER' или 'QUERY'.")

    with open(EXCLUSIONS_FILE, "a") as file:
        file.write(f"{category}:{value}\n")
    
    print(f"Добавлено в исключения: {category} -> {value}")


def is_excluded(ip, user, query):
    """Проверяет, находится ли IP, пользователь или запрос в списке исключений."""
    ip_exclusions, user_exclusions, query_exclusions = load_exclusions()

    if ip in ip_exclusions:
        print(f"IP {ip} в списке исключений, не блокируем.")
        return True
    if user in user_exclusions:
        print(f"Пользователь {user} в списке исключений, не блокируем.")
        return True
    for exclusion in query_exclusions:
        if exclusion in query:
            print(f"Запрос '{query}' содержит исключённую строку '{exclusion}', не блокируем.")
            return True

    return False

# Уведомление администратора по почте
def send_email_notification(email, subject, message):
    # Отправляет email-уведомление.
    sender_email = entry34.get()
    
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = email

    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:  # Укажите SMTP-сервер
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
            print(f"Email-уведомление отправлено на {email}")
    except Exception as e:
        print(f"Ошибка отправки email: {e}")

# Уведомление администратора в Телеграмме
def send_telegram_notification(bot_token, chat_id, message):
    # Отправляет уведомление в Telegram.
telegram_login = entry35.get()
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message}
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Telegram-уведомление отправлено в чат {chat_id}")
        else:
            print(f"Ошибка Telegram API: {response.text}")
    except Exception as e:
        print(f"Ошибка отправки Telegram-сообщения: {e}")

def detect_anomalous_behavior(ip: str, user: str, query: str, threshold=5, time_window=60) -> bool:
    # Выявление аномального поведения: слишком много запросов за короткий период или подозрительные изменения.
    current_time = time.time()
    QUERY_LOGS[ip].append((current_time, query))

    # Фильтруем запросы, оставляем только недавние
    QUERY_LOGS[ip] = [(t, q) for t, q in QUERY_LOGS[ip] if current_time - t <= time_window]

    # Анализ частоты запросов
    if len(QUERY_LOGS[ip]) > threshold:
        print(f"[ALERT] Аномальная активность от {ip} (более {threshold} запросов за {time_window} секунд)")
        return True

    # Анализ структуры запросов (например, изменение паттерна запросов пользователя)
    query_types = set()
    for _, q in QUERY_LOGS[ip]:
        if "SELECT" in q.upper():
            query_types.add("SELECT")
        elif "INSERT" in q.upper():
            query_types.add("INSERT")
        elif "UPDATE" in q.upper():
            query_types.add("UPDATE")
        elif "DELETE" in q.upper():
            query_types.add("DELETE")

    if len(query_types) > 10:  # Например, если в течение минуты используются более 10 разных типов команд
        print(f"[ALERT] Подозрительная смена типов запросов от {user} ({query_types})")
        return True

    return False

root = Tk()
root.title('SQL-Injection')
root.geometry('900x550')
root.resizable(width=False, height=False)

tab_control = ttk.Notebook(root)

tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)
tab3 = ttk.Frame(tab_control)
tab_control.add(tab1, text='Общая информация')
tab_control.add(tab2, text='Безопасность')
tab_control.add(tab3, text='Параметры')

#Вкладка - Общая информация
lb1 = Label(tab1, text="Подключение к серверу:", font=("Arial", 14, "bold"), fg='#130049')
lb1.place(x=50, y=20)

button1 = Button(tab1, text="Установить соединение", font=("Arial", 10, "bold"), bg='#BCD9FF', fg='#130049', command=go_ssh)
button1.place(x=60, y=60, width=180, height=35)

lb2 = Label(tab1, text="Состояние мониторинга:", font=("Arial", 14, "bold"), fg='#130049')
lb2.place(x=50, y=120)


button2 = Button(tab1, text="Запуск мониторинга", font=("Arial", 10, "bold"), bg='#BCD9FF', fg='#130049')
button2.place(x=70, y=160, width=160, height=35)

lb3 = Label(tab1, text="Обнаружение угроз:", font=("Arial", 14, "bold"), fg='#130049')
lb3.place(x=65, y=220)


button3 = Button(tab1, text="Запуск обнаружения", font=("Arial", 10, "bold"), bg='#BCD9FF', fg='#130049')
button3.place(x=70, y=260, width=160, height=35)

lb4 = Label(tab1, text="Информация о сервере", font=("Arial", 14, "bold"), fg='#130049')
lb4.place(x=550, y=120)

lb5 = Label(tab1, text="Операционная система: Ubuntu 22.04.4 LTS", font=("Arial", 11, "bold"), fg='#130049')
lb5.place(x=515, y=160)

lb6 = Label(tab1, text="СУБД: PostgreSQL 16 ver.", font=("Arial", 11, "bold"), fg='#130049')
lb6.place(x=515, y=185)

lb7 = Label(tab1, text="Конфигурация сервера: 4/8 - CPU/RAM", font=("Arial", 11, "bold"), fg='#130049')
lb7.place(x=515, y=210)

# lb8 = Label(tab1, text="Статистика", font=("Arial", 14, "bold"), fg='#130049')
# lb8.place(x=600, y=220)
#
# lb9 = Label(tab1, text="Выполнено запросов:", font=("Arial", 10, "bold"), fg='#130049')
# lb9.place(x=580, y=255)
#
# lb10 = Label(tab1, text="Выполняется в данный момент:", font=("Arial", 10, "bold"), fg='#130049')
# lb10.place(x=555, y=280)
#
# lb11 = Label(tab1, text="Ср. кол-во запросов в сек.:", font=("Arial", 10, "bold"), fg='#130049')
# lb11.place(x=570, y=305)

lb12 = Label(tab1, text="Системные ресурсы", font=("Arial", 12, "bold"), fg='#130049')
lb12.place(x=350, y=420)

lb13 = Label(tab1, text="CPU 27%", font=("Arial", 10, "bold"), fg='#130049')
lb13.place(x=150, y=465)

lb14 = Label(tab1, text="RAM 3,34 / 7,76 GB", font=("Arial", 10, "bold"), fg='#130049')
lb14.place(x=285, y=465)

lb14 = Label(tab1, text="/:30%", font=("Arial", 10, "bold"), fg='#130049')
lb14.place(x=480, y=465)

lb15 = Label(tab1, text="/data/pg_data:/47%", font=("Arial", 10, "bold"), fg='#130049')
lb15.place(x=600, y=465)

#Вкладка - Безопасность

lb22 = Label(tab2, text="Заблокировать / Устранить процесс:", font=("Arial", 12, "bold"), fg='#130049')
lb22.place(x=260, y=10)
lb23 = Label(tab2, text="Имя пользователя:", font=("Arial", 11, "bold"), fg='#130049')
lb23.place(x=60, y=45)
entry21 = Entry(tab2, fg="gray", font=("Arial", 11))
entry21.place(x=215, y=45, width=150)

lb24 = Label(tab2, text="IP-адрес:", font=("Arial", 11, "bold"), fg='#130049')
lb24.place(x=400, y=45)
entry22 = Entry(tab2, fg="gray", font=("Arial", 11))
entry22.place(x=480, y=45, width=150)

lb25 = Label(tab2, text="PID:", font=("Arial", 11, "bold"), fg='#130049')
lb25.place(x=670, y=45)
entry23 = Entry(tab2, fg="gray", font=("Arial", 11))
entry23.place(x=715, y=45, width=100)

button21 = Button(tab2, text="Выполнить", font=("Arial", 10, "bold"), bg='#BCD9FF', fg='#130049')
button21.place(x=320, y=80, width=140, height=30)

lb26 = Label(tab2, text="Список подозрительных запросов: 7", font=("Arial", 12, "bold"), fg='#130049')
lb26.place(x=280, y=130)

# Таблица Treeview
columns = ["DATE", "PID", "USER", "APP", "DATABASE", "QUERY", "IP-address"]
tree = ttk.Treeview(tab2, columns=columns, show="headings", height=12)

# Настройка заголовков
for col in columns:
    if col == "QUERY":
        tree.heading(col, text=col)
        tree.column(col, width=200, anchor="center")
    else:
        tree.heading(col, text=col)
        tree.column(col, width=90, anchor="center")

# Вертикальный скроллбар
scrollbar = ttk.Scrollbar(tab2, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)

# Размещение таблицы и скроллбара
tree.grid(row=2, column=0, columnspan=7, sticky="nsew", padx=5, pady=(160, 0))
scrollbar.grid(row=2, column=7, sticky="ns", pady=(160, 0))

# Настройка растяжения
tab2.grid_rowconfigure(2, weight=1)
tab2.grid_columnconfigure(0, weight=1)

#Вкладка - Параметры
lb31 = Label(tab3, text="Подключение к серверу по SSH", font=("Arial", 14, "bold"), fg='#130049')
lb31.place(x=50, y=20)

lb32 = Label(tab3, text="Сервер", font=("Arial", 12, "bold"), fg='#130049')
lb32.place(x=160, y=50)
lb320 = Label(tab3, text="FQDN или IP:", font=("Arial", 12, "bold"), fg='#130049')
lb320.place(x=30, y=80)
entry31 = Entry(tab3, fg="gray", font=("Arial", 12))
entry31.place(x=150, y=80, width=230)

lb321 = Label(tab3, text="Порт SSH:", font=("Arial", 12, "bold"), fg='#130049')
lb321.place(x=30, y=110)
entry311 = Entry(tab3, fg="gray", font=("Arial", 12))
entry311.place(x=150, y=110, width=80)

lb33 = Label(tab3, text="Авторизация", font=("Arial", 12, "bold"), fg='#130049')
lb33.place(x=140, y=150)
lb34 = Label(tab3, text="Логин:", font=("Arial", 12, "bold"), fg='#130049')
lb34.place(x=100, y=185)
entry32 = Entry(tab3, fg="gray", font=("Arial", 12))
entry32.place(x=190, y=185)
lb35 = Label(tab3, text="Пароль:", font=("Arial", 12, "bold"), fg='#130049')
lb35.place(x=100, y=215)
entry33 = Entry(tab3, fg="gray", font=("Arial", 12))
entry33.place(x=190, y=215)
lb36 = Label(tab3, text="SSH-ключ:", font=("Arial", 12, "bold"), fg='#130049')
lb36.place(x=100, y=252)
button31 = Button(tab3, text="Добавить SSH-ключ", font=("Arial", 10, "bold"), bg='#BCD9FF', fg='#130049')
button31.place(x=200, y=245, width=160, height=35)

lb37 = Label(tab3, text="Уведомления", font=("Arial", 12, "bold"), fg='#130049')
lb37.place(x=150, y=310)
lb38 = Label(tab3, text="Почтовый адрес:", font=("Arial", 12, "bold"), fg='#130049')
lb38.place(x=40, y=350)
entry34 = Entry(tab3, fg="gray", font=("Arial", 12))
entry34.place(x=190, y=350)
lb39 = Label(tab3, text="Telegram:", font=("Arial", 12, "bold"), fg='#130049')
lb39.place(x=65, y=380)
entry35 = Entry(tab3, fg="gray", font=("Arial", 12))
entry35.place(x=190, y=380)
button32 = Button(tab3, text="Сохранить настройки", font=("Arial", 12, "bold"), bg='#BCD9FF', fg='#130049', command=save_to_file)
button32.place(x=340, y=470, width=200, height=35)

lb311 = Label(tab3, text="Основные настройки", font=("Arial", 14, "bold"), fg='#130049')
lb311.place(x=550, y=20)

lb312 = Label(tab3, text="Пусть к файлу с логами", font=("Arial", 12, "bold"), fg='#130049')
lb312.place(x=555, y=50)
entry36 = Entry(tab3, fg="gray", font=("Arial", 12))
entry36.place(x=550, y=80, width=210)

lb313 = Label(tab3, text="Порог для автоблокировки", font=("Arial", 12, "bold"), fg='#130049')
lb313.place(x=545, y=110)
entry37 = Entry(tab3, fg="gray", font=("Arial", 12))
entry37.place(x=550, y=145, width=210)

lb314 = Label(tab3, text="Исключения", font=("Arial", 12, "bold"), fg='#130049')
lb314.place(x=605, y=210)
button34 = Button(tab3, text="Просмотр списка", font=("Arial", 10, "bold"), bg='#BCD9FF', fg='#130049', command=show_exceptions)
button34.place(x=575, y=245, width=160, height=35)
lb313 = Label(tab3, text="Имя пользователя:", font=("Arial", 11, "bold"), fg='#130049')
lb313.place(x=470, y=300)
entry38 = Entry(tab3, fg="gray", font=("Arial", 12))
entry38.place(x=630, y=300, width=210)
lb313 = Label(tab3, text="IP-адрес:", font=("Arial", 11, "bold"), fg='#130049')
lb313.place(x=505, y=330)
entry39 = Entry(tab3, fg="gray", font=("Arial", 12))
entry39.place(x=630, y=330, width=210)
lb313 = Label(tab3, text="Запрос:", font=("Arial", 11, "bold"), fg='#130049')
lb313.place(x=510, y=365)
entry40 = Entry(tab3, fg="gray", font=("Arial", 12))
entry40.place(x=630, y=365, width=210)
button34 = Button(tab3, text="Добавить", font=("Arial", 10, "bold"), bg='#BCD9FF', fg='#130049', command=save_exceptions)
button34.place(x=575, y=400, width=160, height=35)


tab_control.pack(expand=1, fill='both')

root.mainloop()

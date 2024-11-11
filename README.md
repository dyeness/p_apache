| Language |
|----------|
| [Українська](README_UA.md) |
| [English](README.md) |

# Description of all functions
### 1. `parse_logs(file_path)`

**Description**: This is a basic parsing function that processes a log file line by line, extracts the necessary information, saves it to a data structure, and counts the number of attacks (XSS, SQL injection, IDOR).

**Arguments:
- `file_path` (str): The path to the log file (e.g. `access.log`) to be analysed.

**Returns**:
- `pd.DataFrame`: A DataFrame containing the IP addresses and URLs of each request.
- `xss_attempts` (int): The number of XSS attacks found in the logs.
- `sqli_attempts` (int): The number of SQL injections found in the logs.
- `idor_attempts` (int): The number of IDOR attacks found in the logs.

**Algorithm**:
1. Initialises an empty `data` list to store information about IP and URL, as well as attack counters (`xss_attempts`, `qli_attempts`, `idor_attempts`).
2. Opens the log file and reads it line by line.
3. For each line:
   - Extracts the IP address using a regular expression.
   - Extracts the URL from an HTTP request using a regular expression.
   - Checks the URL for patterns that indicate XSS, SQL injection, or IDOR attacks and increments the corresponding counter if a match is found.
   - Adds the IP and URL to the `data` list.
4. Returns a DataFrame containing the IP and URL for each request, as well as the number of attacks for each type.

**Function code**:
```python
def parse_logs(file_path):
    data = []
    xss_attempts = 0
    sqli_attempts = 0
    idor_attempts = 0
    
    with open(file_path, ‘r’) as file:
        for line in file:
            ip_match = re.match(r‘(\d+\.\d+\.\d+\.\d+)’, line)
            url_match = re.search(r‘\’[A-Z]+\s(.*?)\sHTTP', line)
            
            if ip_match and url_match:
                ip = ip_match.group(1)
                url = url_match.group(1)
                
                # Checking for XSS, SQL injection and IDOR
                if any(pattern in url for pattern in xss_patterns):
                    xss_attempts += 1
                if any(pattern in url for pattern in sqli_patterns):
                    sqli_attempts += 1
                if any(pattern in url for pattern in idor_patterns):
                    idor_attempts += 1
                
                data.append({‘IP’: ip, ‘URL’: url})
    
    return pd.DataFrame(data), xss_attempts, sqli_attempts, idor_attempts
```

### 2. The main code (without a named function)

All other parts of the code are not wrapped in a separate function, but they perform the following tasks:

#### Grouping and sorting data

**Description: Groups data by a combination of IP addresses and URLs, and counts the number of requests for each combination. The data is then sorted in descending order of the number of requests.**

**Code**:
```python
ip_url_counts = data_frame.groupby([‘IP’, ‘URL’]).size().reset_index(name=‘Count’)
ip_url_counts = ip_url_counts.sort_values(by=‘Count’, ascending=False)
```

#### Saving data to CSV

**Description: Saves the results to three different CSV files:
- `top_ip_url_full.csv`: Contains the full list of IP and URL combinations with the number of requests for each combination.
- `top_ip_url_10.csv`: Contains the top 10 IP and URL combinations.
- `top_ip_url_100.csv`: Contains the top 100 IP and URL combinations.

**Code**:
``python
ip_url_counts.to_csv(‘top_ip_url_full.csv’, index=False, sep=‘\t’)
ip_url_counts.head(10).to_csv(‘top_ip_url_10.csv’, index=False, sep=‘\t’)
ip_url_counts.head(100).to_csv(‘top_ip_url_100.csv’, index=False, sep=‘\t’)
```

#### Graph Display.

**Description: Plots a horizontal bar chart showing the top 10 IP addresses by number of requests, using the `matplotlib` library.**

**Code**:
```python
ip_url_counts.head(10).plot(kind=‘barh’, x=‘IP’, y=‘Count’, title=‘Top 10 IPs by Request Count’)
plt.xlabel(‘Number of Requests’)
plt.ylabel(‘IP Addresses’)
plt.gca().invert_yaxis()
plt.show()
```

#### Displaying attack statistics

**Description: Prints the number of detected attacks of each type to the console: XSS, SQL injection and IDOR.**

**Code**:

```python
print(f ‘Number of XSS attacks: {xss_attempts}’)
print(f ‘Number of SQL injections: {sqli_attempts}’)
print(f ‘Number of IDOR attacks: {idor_attempts}’)
```

### Suggestion: Structure the main code as functions

To make the parser more flexible and modular, you can structure the main code as functions:

1. **`group_and_sort_data(data_frame)`** - for grouping and sorting data.
2. **`save_to_csv(data, filename, top_n=None)`** - to save data to CSV (including partial and full reports).
3. **`plot_top_ips(data_frame, top_n=10)`** - to plot the top IP addresses.

This will make the parser more convenient to extend and use in different scenarios.

# Description of libraries

### 1. `re` - library for working with regular expressions

The `re` library (included in the standard Python library) is used to parse log files. Regular expressions allow you to find certain patterns in the text, which is useful for extracting parts of strings from logs, such as IP addresses and URL requests.

#### In the code:
- **`re.match(r‘(\d+\.\d+\.\d+)’, line)`**: used to find the IP address at the beginning of a line.
- **`re.search(r‘\’[A-Z]+\s(.*?)\sHTTP', line)`**: used to find the URL request in the string.

### 2. `pandas` - a library for working with data

`pandas` is a powerful library for data processing and analysis, which allows you to work with data tables, perform grouping, sorting and save the results in various formats (for example, in CSV).

#### In the code:
- **`pd.DataFrame(data)`**: creates a table (DataFrame) with data collected from the log file.
- **`data_frame[‘IP’].value_counts().head(10)`**: counts the number of requests from each IP address, and then selects the top 10 IPs by the number of requests.
- **`ip_counts.to_csv(‘top_ips.csv’)`**: Saves the results to a CSV file, which allows you to save the counted data for further analysis.

### 3. `matplotlib.pyplot` - library for plotting graphs

`matplotlib.pyplot` is a library for plotting graphs in Python. It allows you to create a variety of graphical visualisations, including line graphs, bar graphs, charts, etc.

#### In the code:
- **`ip_counts.plot(kind=‘barh’, title=‘Top 10 IPs by Request Count’)`**: creates a horizontal bar chart showing the top 10 IP addresses by request count.
- **`plt.xlabel(‘Number of Requests’)`** and **`plt.ylabel(‘IP Addresses’)`**: set the labels for the X and Y axes.
- **`plt.gca().invert_yaxis()`**: inverts the Y-axis so that the most popular IP addresses are at the top of the graph.
- **`plt.show()`**: displays the graph on the screen.

### Briefly:

- **`re`** is used to parse text and extract information (IP, URL).
- **`pandas`** is used for data processing, grouping, sorting and exporting to CSV.
- **`matplotlib.pyplot** is used to build a graph that visualises the results (top 10 IPs by number of requests).

Together, these libraries allow you to read the log file, analyse it, save the results, and plot the data for easier understanding.

# Question

#### 1. How are IP addresses and URLs extracted from the logs?

**Answer:  
##### Regular expressions are used to extract IP addresses and URLs from logs. The IP address is extracted from the beginning of the line using the regular expression `r‘(\d+\.\d+\.\d+\.\d+)’`, and the URL is extracted using the expression `r‘\’[A-Z]+\s(.*?)\sHTTP'`, which finds the URL between the request method (GET, POST, etc.) and the protocol (HTTP/1.1).

---

#### 2. How are the analysis results stored?

**Answer**:  
##### The results are stored in three CSV files:
- **`top_ip_url_full.csv`**: contains a complete list of IP address and URL combinations with the number of requests for each.
- **`top_ip_url_10.csv`**: contains the top 10 combinations of IP addresses and URLs by the number of requests.
- **`top_ip_url_100.csv`**: contains the top 100 IP and URL combinations by the number of requests.  
Each file uses a single tab character as a separator between columns.

---

#### 3. Is it possible to change the number of records in partial reports?

**Answer**:  
##### Yes, you can change the number of records in partial reports by changing the `head(10)` and `head(100)` parameters to the desired value, or by passing the parameter to a function if you reorganise the code. For example, if you want the top 20, just change `head(10)` to `head(20)`.

---

#### 4. How does the code build the graph?

**Answer**:  
##### The code uses the `matplotlib` library to build a horizontal bar chart. It shows the top 10 IP addresses by the number of requests, where the IP addresses are on the Y-axis and the number of requests is on the X-axis. This allows you to quickly see the most active IP addresses on the server.

---

#### 5. What should I do if the structure of the logs is different?

**Answer**:  
##### If the structure of the logs is different (for example, logs from Nginx instead of Apache), you need to change the regular expressions in `parse_logs` that are used to extract IP addresses and URLs. This will allow you to adapt the code to the new log format.

---

#### 6. What libraries are used and why?

**Answer**:  
##### The code uses the following libraries:
##### - **`re`**: for working with regular expressions that help to extract IP addresses and URLs from logs.
##### - **`pandas****: for data processing, including DataFrame creation, grouping, sorting and saving to CSV format.
##### - **`matplotlib.pyplot**: to build a graph showing the top 10 IP addresses by number of requests.

---

#### 7. Is it possible to extend the code to analyse multiple files?

**Answer**:  
##### Yes, the code can be easily adapted to process multiple files by adding a loop to read all files in the logs directory. Each file can be processed with the `parse_logs` function, and then the results can be combined into a common DataFrame before grouping and saving.

---

#### 8. How does this code define partial and complete information?

**Answer**:  
##### The code generates three reports:
##### - The full report (`top_ip_url_full.csv`) contains all log entries where IP addresses are matched with URLs.
##### - The partial reports (`top_ip_url_10.csv` and `top_ip_url_100.csv`) contain only the top 10 and top 100 entries, respectively. This allows users to get a summary report or a detailed report, depending on their needs.

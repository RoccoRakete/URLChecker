import requests

# Function to check if a URL is reachable
def check_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(e)
        return False

# Function to write results to a text file
def write_results(results):
    with open('results.txt', 'w') as file:
        for result in results:
            file.write(result + '\n')

# Open the file with the list of URLs and save them to a list
with open('urls.txt', 'r') as file:
    urls = [line.strip() for line in file]

# Check each URL in the list and save the results to a list
results = []
for url in urls:
    if check_url(url):
        result = url + " is reachable"
    else:
        result = url + " is not reachable"
    results.append(result)

# Write the results to a text file
write_results(results)


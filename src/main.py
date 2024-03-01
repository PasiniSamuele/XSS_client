import pandas as pd

from utils.request_tools import do_xss_post_request
from utils.html_tools import is_same_dom

# endpoint = 'http://host.docker.internal:5555/vuln_backend/1.0/endpoint/'
endpoint = 'http://localhost:5555/vuln_backend/1.0/endpoint/'
payload_xss_file = "./payloads/payload_form_basic.txt"
payload_xss_obf_file = "./payloads/payload_form.txt"
payload_not_xss_file = "./payloads/payload_not_xss.txt"

with open(payload_xss_file, 'r') as f:
    payload_xss = f.read()
with open(payload_xss_obf_file, 'r') as f:
    payload_xss_obf = f.read()
with open(payload_not_xss_file, 'r') as f:
    payload_not_xss = f.read()

html_xss = do_xss_post_request(endpoint, payload_xss)
html_xss_obf = do_xss_post_request(endpoint, payload_xss_obf)
html_not_xss = do_xss_post_request(endpoint, payload_not_xss)

is_same_xss = is_same_dom(html_xss, html_xss_obf)
is_same_not_xss = is_same_dom(html_xss, html_not_xss)
# print(is_same_xss, is_same_not_xss)


# Load payloads from file
payload_xss_csv_file = "./../../data/Payloads_relevant.csv"
payload_xss_df = pd.read_csv(payload_xss_csv_file)

print("Total Size of Dataset: ", payload_xss_df.shape[0])

# Filter benign and malicious payloads
benign_xss = payload_xss_df[payload_xss_df['Class'] == "Benign"]
# marked_benign_xss = benign_xss
marked_benign_xss = pd.read_csv("./../../data/Payloads_benign_marked.csv")

# Get random benign payload
random_benign_xss = marked_benign_xss.sample(n=1).iloc[0]
while random_benign_xss["Wrong Class"]:
    random_benign_xss = marked_benign_xss.sample(n=1).iloc[0]
    print("Random Benign XSS: ", random_benign_xss["Payloads"])
random_benign_xss = random_benign_xss["Payloads"]
html_xss_benign_rand = do_xss_post_request(endpoint, random_benign_xss)

marked_benign_xss["Wrong Class"] = False

# Test if benign payloads have the same dom as the random benign payload
for index, row in marked_benign_xss.iterrows():
    html_xss_benign = do_xss_post_request(endpoint, row["Payloads"])
    is_same_xss_benign = is_same_dom(html_xss_benign_rand, html_xss_benign)
    if not is_same_xss_benign:
        print(html_xss_benign_rand, html_xss_benign)
        marked_benign_xss.at[index, "Wrong Class"] = True
wrongly_marked_benign_size = marked_benign_xss[marked_benign_xss["Wrong Class"] == True].shape[0]
print("Wrongly classified benign payloads: ", f"{wrongly_marked_benign_size}/{marked_benign_xss.shape[0]}")
marked_benign_xss.to_csv("./../../data/Payloads_benign_marked.csv", index=False)


# Test if malicious payloads have different dom as the random benign payload
malicious_xss = payload_xss_df[payload_xss_df['Class'] == "Malicious"]
marked_malicious_xss = malicious_xss
marked_malicious_xss["Wrong Class"] = False

for index, row in malicious_xss.iterrows():
    html_xss_malicious = do_xss_post_request(endpoint, row["Payloads"])
    is_same_xss_malicious = is_same_dom(html_xss_benign_rand, html_xss_malicious)
    if is_same_xss_malicious:
        # print(html_xss_benign_rand, html_xss_malicious)
        marked_malicious_xss.at[index, "Wrong Class"] = True
wrongly_marked_malicious_size = marked_malicious_xss[marked_malicious_xss["Wrong Class"] == True].shape[0]
print("Wrongly classified malicious payloads: ", f"{wrongly_marked_malicious_size}/{marked_malicious_xss.shape[0]}")

marked_malicious_xss.to_csv("./../../data/Payloads_malicious_marked.csv", index=False)


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

payload_xss_csv_file = "./../../data/Payloads_relevant.csv"
with open(payload_xss_csv_file, 'r') as f:
    for line in f:
        if not line.startswith('http'):
            continue
        index = line.rfind(',')
        payload_xss = line[0:index]
        html_xss_line = do_xss_post_request(endpoint, payload_xss)
        print(html_xss_line)
        # break

is_same_xss = is_same_dom(html_xss, html_xss_obf)
is_same_not_xss = is_same_dom(html_xss, html_not_xss)
# print(is_same_xss, is_same_not_xss)
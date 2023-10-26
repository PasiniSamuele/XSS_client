from utils.request_tools import do_xss_post_request
from utils.html_tools import is_same_dom

endpoint = 'http://host.docker.internal:5555/vuln_backend/1.0/endpoint/'
payload_xss_file = "src/payloads/payload_form_basic.txt"
payload_xss_obf_file = "src/payloads/payload_form.txt"
payload_not_xss_file ="src/payloads/payload_not_xss.txt"

with open(payload_xss_file, 'r') as f:
    payload_xss = f.read()
with open(payload_xss_obf_file, 'r') as f:
    payload_xss_obf = f.read()
with open(payload_not_xss_file, 'r') as f:
    payload_not_xss = f.read()

html_xss = do_xss_post_request(endpoint,payload_xss)
html_xss_obf = do_xss_post_request(endpoint,payload_xss_obf)
html_not_xss = do_xss_post_request(endpoint,payload_not_xss)


is_same_xss = is_same_dom(html_xss, html_xss_obf)
is_same_not_xss = is_same_dom(html_xss, html_not_xss)
print(is_same_xss, is_same_not_xss)
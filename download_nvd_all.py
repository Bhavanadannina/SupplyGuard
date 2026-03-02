import os
import requests
import gzip
import shutil

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/"
START_YEAR = 2002
END_YEAR = 2025   # Change later if needed

os.makedirs("dataset", exist_ok=True)

for year in range(START_YEAR, END_YEAR + 1):
    filename = f"nvdcve-2.0-{year}.json"
    gz_filename = filename + ".gz"
    url = BASE_URL + gz_filename

    print(f"Downloading {gz_filename}...")

    try:
        response = requests.get(url, stream=True, timeout=60)

        if response.status_code == 200:
            gz_path = os.path.join("dataset", gz_filename)
            json_path = os.path.join("dataset", filename)

            # Save .gz file
            with open(gz_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Extract .gz
            with gzip.open(gz_path, "rb") as f_in:
                with open(json_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Delete compressed file to save space
            os.remove(gz_path)

            print(f"Saved {filename}")

        else:
            print(f"Failed for {year}")

    except Exception as e:
        print(f"Error downloading {year}: {e}")

print("All NVD feeds downloaded successfully.")
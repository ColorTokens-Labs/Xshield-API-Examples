# Tagging assets in the new Xshield Platform from CSV data

The script tag_assets.py reads a CSV file containing tag definitions for assets, and 
uses the Xshield APIs to tag the assets within the platform.

The sample CSV specifies the mandatory header line and a couple of examples.

Authentication credentials must be specified in the file config.json in the same directory.
A template for this file is included here.

The script's requirements can be installed using the provided requirements file.

```
pip install -r requirements.txt
```

To run the script:

```
python3 tag_assets.py
```

The script is terse and will display messages only if it encounters an error while parsing the 
CSV file or invoking the API.  No news is good news!

import json
from yaml import load, Loader
import os

file_list = []
for fpath, _, fnames in os.walk("playground/nuclei-templates/"):
    for file in fnames:
        _, ext = os.path.splitext(file)
        if ext != ".yaml":
            continue
        file_list.append(f"{fpath}/{file}")

yaml_files = []
for file in file_list:
    with open(file) as f:
        raw_file = f.read()
    yaml_file = load(raw_file, Loader=Loader)
    yaml_files.append(yaml_file)

with open("playground/yaml_json.json", "w") as f:
    f.write(json.dumps(yaml_files, indent=4))

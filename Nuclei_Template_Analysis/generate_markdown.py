import json
import sys
import os


def search_by_tags(search_term):
    results = []
    for yaml_file in yaml_files:
        if "tags" in yaml_file["info"]:
            tags = yaml_file["info"]["tags"]
            if search_term in tags:
                results.append(yaml_file)

    return results


def show_description(data):
    text = ""
    text += f"# {data['info']['name']}\n"
    if "description" in data["info"]:
        text += f"## Description\n"
        text += f"- {data['info']['description']}\n"
    if "severity" in data["info"]:
        text += f"- severity - {data['info']['severity']}\n"
    if "tags" in data["info"]:
        text += f"- tags - {data['info']['tags']}\n"
    text = text.replace('<', '\<')
    return text


def show_matchers(matchers, match=True):
    text = ""
    if match:
        text += "### Matchers\n"
    else:
        text += "### Extractors\n"
    for matcher in matchers:
        for k, v in matcher.items():
            if k == "type":
                text += f"\n**Type - {v}**\n"
                continue
            if isinstance(v, list):
                text += f"- {k}\n"
                for idx, l in enumerate(v):
                    text += f"    {idx+1}. {l}\n"
            else:
                text += f"- {k} - {v}\n"
    text = text.replace('<', '\<')
    return text


def show_urls(paths):
    text = ""
    text += "### URL\n"
    for url in paths:
        text += f"- {url}\n"
    text = text.replace('<', '\<')
    return text


def show_requests(data):
    text = ""
    if "requests" in data:
        text += "## Requests\n"
        requests = data["requests"][0]
        if "method" in requests:
            method = requests["method"]
            text += f"- Method - {method}\n"
            if method == "GET":
                if "path" in requests:
                    text += show_urls(requests["path"])
                if "matchers" in requests:
                    text += show_matchers(requests["matchers"])
                if "extractors" in requests:
                    text += show_matchers(requests["extractors"], match=False)
            if method == "POST":
                text += f"- Method - {method}\n"
                text += show_urls(requests["path"])
                if "body" in requests:
                    text += f"  - {requests['body']}\n"
                if "matchers" in requests:
                    text += show_matchers(requests["matchers"])
                if "extractors" in requests:
                    text += show_matchers(requests["extractors"], match=False)
        if "raw" in requests:
            raw_reqs = requests["raw"]
            for idx, raw_req in enumerate(raw_reqs):
                text += f"### Step - {idx + 1}\n"
                text += "```"
                text += f"\n{raw_req}\n"
                text += "```"
                text += "\n"
            if "matchers" in requests:
                text += show_matchers(requests["matchers"])
            if "extractors" in requests:
                text += show_matchers(requests["extractors"], match=False)
        if "payloads" in requests:
            text += "\n**Payloads**"
            for payload in requests["payloads"]:
                text += f"- {payload}\n"
    return text


def save_as_markdown(name):
    yaml_list = search_by_tags(name)
    result = ""
    for data in yaml_list:
        result += show_description(data)
        result += show_requests(data)
        result += "\n---\n"
    if len(result) == 0:
        print("[!] No such category")
        sys.exit()
    if not os.path.exists("markdowns"):
        os.mkdir("markdowns")
    fpath = os.path.join("markdowns", f"{name}.md")
    with open(fpath, "w") as f:
        f.write(result)


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"[x] Format - python generate_markdown.py category")
        print(f"[!] category like sqli, lfi, xss which are tags in nuclei template")
        sys.exit()

    with open("playground/yaml_json.json", "r") as f:
        d = f.read()
        yaml_files = json.loads(d)
    save_as_markdown(sys.argv[1])
    print(f"[!] Successfully saved as {sys.argv[1]}.md in markdowns folder.")

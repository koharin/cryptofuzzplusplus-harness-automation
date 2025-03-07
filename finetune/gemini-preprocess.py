import os 
import json 
import argparse
from tqdm import tqdm

def get_arg():
    parser = argparse.ArgumentParser(description="python gemini-preprocess.py -i output.jsonl")
    parser.add_argument("-i", "--input", help="python gemini-preprocess.py [-h] [-i FILE_PATH]")

    args = parser.parse_args()

    if args:
        return args 
    else:
        return None

def start():
    arg=get_arg()
    dataset=arg.input
    listing=dict()

    output_file=os.path.join(os.getcwd(), 'data', 'preprocess', 'dataset-gemini.jsonl')

    with open(os.path.join(os.getcwd(), 'data', 'preprocess', dataset), 'r', encoding='utf-8') as file:
        for line in tqdm(file):
            data=json.loads(line)
            instruction=data["messages"][0]["content"]
            request=data["messages"][1]["content"]
            answer=data["messages"][2]["content"]

            data = {
                    "systemInstruction": {
                        "role": "system",
                        "parts": [
                        {
                            "text": instruction
                        }
                        ]
                    },
                    "contents": [
                        {
                        "role": "user",
                        "parts": [
                            {
                            "text": request
                            }
                        ]
                        },
                        {
                        "role": "model",
                        "parts": [
                            {
                            "text": answer
                            }
                        ]
                        }
                    ]
                    } 
            with open(output_file, 'a', encoding='utf-8') as file:
                json_str = json.dumps(data, ensure_ascii=False)
                file.write(json_str + '\n')            


if __name__ == "__main__":
    start()
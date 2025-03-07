import argparse
import os
import signal
import time
import google.generativeai as genai
from tqdm import tqdm
import json

def get_arg():
    parser = argparse.ArgumentParser(description="python finetune-gemini.py -i output.jsonl")
    parser.add_argument("-i", "--input", help="python finetune-gemini.py [-h] [-i FILE_PATH]")

    args = parser.parse_args()

    if args:
        return args 
    else:
        return None

def start():
    # Get dataset
    arg=get_arg()
    dataset=arg.input  

    # Set api_key
    genai.configure(api_key="")

    print("[+] Get Dataset")
    training_data=list()
    with open(os.path.join(os.getcwd(), 'data', 'preprocess', dataset), 'r', encoding='utf-8') as file:
        for line in tqdm(file):
            training_data.append(json.loads(line.strip()))
    print(training_data)

    operation = genai.create_tuned_model(
        display_name="cryptofuzz",
        source_model="models/gemini-1.5-flash-001-tuning",
        epoch_count=3,
        batch_size=1,
        learning_rate=0.001,
        training_data=training_data,
    )

    for status in operation.wait_bar():
        time.sleep(10)
    
    result = operation.result()
    print("[+] Result of Gemini finetuning")
    print(result)

    print("[+] Print Tuned Model Info")
    model = genai.GenerativeModel(model_name=result.name)
    print(model)


if __name__ == "__main__":
    start()
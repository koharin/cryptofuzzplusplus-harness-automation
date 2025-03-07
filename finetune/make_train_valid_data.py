import os
import argparse
import json
from tqdm import tqdm

def get_arg():
    parser = argparse.ArgumentParser(description="python make_train_valid_data.py -i output.jsonl -l CRYPTO_LIBRARY_NAME")
    parser.add_argument("-i", "--input", help="python make_train_valid_data.py [-h] [-i FILE_PATH]")
    parser.add_argument("-l", "--library", help="python make_train_valid_data.py [-h] [-l CRYPTO_LIBRARY_NAME]")

    args = parser.parse_args()

    if args:
        return args 
    else:
        return None

def make_train_valid_data(dataset, library):
    train_dataset=os.path.join(os.getcwd(), 'data', 'preprocess', library, 'train.jsonl')
    valid_dataset=os.path.join(os.getcwd(), 'data', 'preprocess', library, 'valid.jsonl')
    listing=dict()
    
    with open(os.path.join(os.getcwd(), 'data', 'preprocess', library, dataset), 'r', encoding='utf-8') as file:
        for line in tqdm(file):
            data=json.loads(line)
            filename=data["messages"][1]["content"].split()[4]
            if filename not in listing:
                listing[filename]=list()
            listing[filename].append(data)
    for key,item in listing.items():
        valid_start_index=int(len(item)*0.8)
        print(f"[+] making training dataset for {key}")
        for i in tqdm(range(0,valid_start_index)):
            with open(train_dataset, 'a', encoding='utf-8') as file2:
                json_str=json.dumps(item[i], ensure_ascii=False)
                file2.write(json_str+'\n')
        print(f"[+] making valid dataset for {filename}")
        for i in tqdm(range(valid_start_index, len(item))):
            with open(valid_dataset, 'a', encoding='utf-8') as file2:
                json_str=json.dumps(item[i], ensure_ascii=False)
                file2.write(json_str+'\n')


def start():
    arg=get_arg()
    dataset=arg.input
    library=arg.library

    make_train_valid_data(dataset, library)

if __name__ == "__main__":
    start()
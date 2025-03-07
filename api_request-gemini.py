import os
import google.generativeai as genai
import signal
import time
import argparse
from util import parse
from util import load_config_file
from prompt_build_gemini import prepare_prompt
from insert import insertion

current_path = os.getcwd()

def get_argument():
    # Initialize parser
    parser = argparse.ArgumentParser(description="python api_request.py [-h] [-c config file path]")

    # Add argument
    parser.add_argument("-c", "--config", help="python api_request.py [-h] [-c config file path]")
    args = parser.parse_args()

    if args:
        return args 
    else:
        return None

def request(prompt):
    ret = None

    # Set api_key
    genai.configure(api_key="")

    while ret is None:
        try:
            model = genai.GenerativeModel('gemini-1.5-pro-001')
            ret = model.generate_content(prompt)
        except Exception as e:
            print(e)
            print("Unknown Error. Waiting...")
            signal.alarm(0) # cancel alarm
            time.sleep(1)
    return ret

def start():
    # parse argument and save 
    argument = get_argument()
    config_file = argument.config
    print(f"config file: {config_file}")

    # get configuration information
    if config_file is None:
        print("[-] Unable to get config data")
        return
    
    config_dict = load_config_file(current_path, config_file)

    documentation = config_dict["algorithm"]["documentation"]
    example_code_path = config_dict["algorithm"]["example_code"]
    argument = config_dict["algorithm"]["arguments"]
    file_to_create = config_dict["algorithm"]["file_to_create"].split(',')
    output = config_dict["algorithm"]["output"]
    algorithm_name = config_dict["algorithm"]["algorithm_name"]
    algorithm_code = config_dict["algorithm"]["algorithm_code"]
    cryptofuzz_dir = config_dict["algorithm"]["cryptofuzz_dir"]
    files = config_dict["files"]

    # path to output directory
    output_dir =  os.path.join(os.getcwd(),"output-gemini", algorithm_name, output)
    print(f"output_dir: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)  

    for i in range(len(file_to_create)):
        dependency=""
        # get dependency of file to create
        for file_inst in files:
            if file_inst.get('name') == file_to_create[i]:
                dependency=file_inst.get('dependency').split(',')

        # prepare prompt
        prompt = prepare_prompt(current_path,algorithm_name, documentation, example_code_path, argument, output_dir, file_to_create[i], algorithm_code,dependency)
        print(f"prompt:\n{prompt}")

        # get response from Gemini
        response = request(prompt)
        if response is None:
            print(response)
            return
        
        output_path = os.path.join(output_dir, file_to_create[i])
        print(f"output_path: {output_path}") 

        print(f"response:\n{response.text}")
        code = parse(response.text)
        try:
            with open(output_path, "w", encoding='utf-8') as file:
                file.write(code)
            #insertion(output_path, file_to_create[i], cryptofuzz_dir)
        except Exception as e:
            print(f"file write error: {e}")
        


if __name__ == "__main__":
    start()

import os
import openai
import signal
import time
import argparse
from util import parse
from util import load_config_file
from prompt_build_without import prepare_prompt
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

    while ret is None:
        try:
            client = openai.OpenAI(
                api_key = ""
            )
            
            ret = client.chat.completions.create(
                model = "gpt-4o",
                messages = [{"role":"system", "content":"You are a code generator specialized in cryptographic libraries."},
                {"role":"user", "content":prompt}
                ]
            )
        except openai.RateLimitError as e:
            #Handle rate limit error, e.g. wait or log
            print(f"OpenAI API request exceeded rate limit: {e}")
            signal.alarm(0)
            time.sleep(5)
        except openai.BadRequestError as e:
            #Handle invalid request error, e.g. validate parameters or log
            print(f"OpenAI API request was invalid: {e}")
            signal.alarm(0)
        except openai.AuthenticationError as e:
            #Handle authentication error, e.g. check credentials or log
            print(f"OpenAI API request was not authorized: {e}")
            signal.alarm(0)
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
    output_dir =  os.path.join(os.getcwd(),"output-gpt-without-finetune", algorithm_name, output)
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

        # get response from GPT
        response = request(prompt)
        if response is None:
            print(response)
            return
        
        output_path = os.path.join(output_dir, file_to_create[i])
        print(f"output_path: {output_path}") 

        print(f"response:\n{response.choices[0].message.content}")
        code = parse(response.choices[0].message.content)
        try:
            with open(output_path, "w", encoding='utf-8') as file:
                file.write(code)
            #insertion(output_path, file_to_create[i], cryptofuzz_dir)
        except Exception as e:
            print(f"file write error: {e}")
        


if __name__ == "__main__":
    start()

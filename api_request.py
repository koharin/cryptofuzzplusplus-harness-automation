import os
import openai
import signal
import time
import argparse
from util import parse
from util import load_config_file
from prompt_build import prepare_prompt
from insert import insertion

current_path = os.getcwd()

def get_argument():
    # Initialize parser
    parser = argparse.ArgumentParser(description="python api_request.py [-h] -f FILE_PATH -a ALGORITHM [-m mode(update,new)] [-r reference file] [-c config file path]")

    # Add argument
    parser.add_argument("-f", "--file_path", help="python api_request.py [-h] [-f FILE_PATH]")
    parser.add_argument("-a", "--algorithm", help="python api_request.py [-h] [-a ALGORITHM]")
    parser.add_argument("-m", "--mode", help="python api_request.py [-h] [-m mode(update,new)]")
    parser.add_argument("-r", "--reference", help="python api_request.py [-h] [-r reference file]")
    parser.add_argument("-c", "--config", help="python api_request.py [-h] [-c config file path]")
    parser.add_argument("-l", "--library", help="python api_request.py [-h] [-l crypto_lib_name]")
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
                model = "ft:gpt-4o-2024-08-06:personal::AfMV7c28",
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
    global algorithm, file_path
    # parse argument and save 
    argument = get_argument()
    file_path = argument.file_path 
    print(f"file path: {file_path}")
    algorithm = argument.algorithm
    print(f"algorithm: {algorithm}")
    mode = argument.mode
    print(f"mode: {mode}")
    reference_file = argument.reference 
    print(f"reference: {reference_file}")
    config_file = argument.config
    print(f"config file: {config_file}")
    library_name=argument.library
    print(f"crypto library: {library_name}")

    # get configuration information
    if config_file is None:
        print("[-] Unable to get config data")
        return
    
    config_dict = load_config_file(current_path, library_name, config_file)

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
    output_dir =  os.path.join(os.getcwd(),"output", library_name, algorithm_name, output)
    print(f"output_dir: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)  

    for i in range(len(file_to_create)):
        dependency=""
        # get dependency of file to create
        for file_inst in files:
            if file_inst.get('name') == file_to_create[i]:
                dependency=file_inst.get('dependency').split(',')

        # prepare prompt
        prompt = prepare_prompt(current_path,mode,algorithm_name, documentation, example_code_path, argument, output_dir, file_to_create[i], algorithm_code,dependency, library_name)
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
            insertion(output_path, file_to_create[i], cryptofuzz_dir, library_name, algorithm_name)
        except Exception as e:
            print(f"file write error: {e}")
        


if __name__ == "__main__":
    start()

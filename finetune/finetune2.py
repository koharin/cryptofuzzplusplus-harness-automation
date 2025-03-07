import openai
import argparse
import os
import signal
import time

def get_argument():
    parser = argparse.ArgumentParser(description="python finetune.py -t training_data.jsonl -v valid.jsonl -l library_name")
    parser.add_argument("-t", "--train", help="python finetune.py [-h] [-t FILE_PATH]")
    parser.add_argument("-v", "--valid", help="python finetune.py [-h] [-v FILE_PATH]")
    parser.add_argument("-l", "--library", help="python finetune.py [-h] [-l CRYPTO_LIBRARY]")

    args = parser.parse_args()

    if args:
        return args 
    else:
        return None

def request(training_file_id, valid_file_id, client):
    ret = None
    while ret is None:
        try:
            # create fine-tuned model. fine-tuning.job object is returned
            print("[+] Prepare finetune")
            ret =  client.fine_tuning.jobs.create(
                training_file=training_file_id,
                validation_file=valid_file_id,
                model="ft:gpt-4o-2024-08-06:personal::ATnJB5gD"
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
    args = get_argument()
    training_file = args.train
    library=args.library
    training_file = os.path.join(os.getcwd(), "data", "preprocess", library, training_file)
    valid_file = args.valid
    valid_file = os.path.join(os.getcwd(), "data", "preprocess", library, valid_file)

    client = openai.OpenAI(
        api_key = ""
    )
    # uploading training file. file ID is returned when the training file was uploaded to the OpenAI API
    print("[+] upload training data to OPENAI API")
    training_file = client.files.create(
        file=open(training_file, "rb"),
        purpose="fine-tune"
    )
    valid_file=client.files.create(
        file=open(valid_file, "rb"),
        purpose="fine-tune"
    )
    print(f"training_file: {training_file}")
    training_file_id=str(training_file).split("'")[1]
    valid_file_id=str(valid_file).split("'")[1]

    print(f"training_file_id: {training_file_id}")
    print(f"valid_file_id: {valid_file_id}")

    finetune_job = request(training_file_id, valid_file_id, client)

    # when a job has succeeded, use fine-tuned model as normal
    print(f"[+] Staring {finetune_job}")

if __name__ == "__main__":
    start()
import openai
import os
from dotenv import load_dotenv

def setup_openai():
    load_dotenv()
    model_engine = "gpt-3.5-turbo-instruct"
    return model_engine
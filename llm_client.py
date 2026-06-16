"""
Author: Abraham Yelifari
Created: 4/23/2026
"""
from llama_cpp import Llama
from datetime import datetime

import requests
import time


class OllamaClient:
    """
    Used to communicate with OLLAMA server that was installed for api purposes.
    """
    def __init__(self, model: str, location: str = "http://localhost:11434/api/chat"):
        """
        Creates a new OllamaClient instance with api capabilities.
        :param model: The LLM to be used.
        :param location: The URL to the installation of the LLM; if installed then it will be in localhost
        with the port that was specified when installing. The default URL is (http://localhost:11434/api/chat)
        where 11434 is the port number.
        """
        self.model = model
        self.location = location

    def prompt(self, system_prompt: str, user_prompt: str) -> dict:
        """
        Sends the prompt to the local model installed at the self.location when the object was created.
        The default location is http://localhost:11434/api/chat.
        :param system_prompt: The system prompt text. The LLM is told that the system should operate with
        this prompt.
        :param user_prompt: The user prompt text. The LLM is told that the user should operate with
        this prompt.
        :return: The json returned from the LLM, as a python dictionary.
        """
        msg = {
          "model": self.model,
          "messages": [
            {
              "role": "system",
              "content": system_prompt
            },
            {
              "role": "user",
              "content": user_prompt
            }
          ],
          "format": "json",
          "stream": False
        }
        response = requests.post(self.location, json=msg)
        data = response.json()
        return data

class OllamaGPU:
    """
    Used to communicate with an installation of an Ollama instance to be run on the GPU.
    """
    def __init__(self, path: str, n_ctx: int = 2048, n_gpu_layers: int = -1):
        """
        Creates a new Ollama GPU instance.
        :param path: The file path to the installed LLM instance.
        :param n_ctx: Context window size (default 2048).
        :param n_gpu_layers: Number of layers to offload to GPU (defaults to -1 for all).
        """
        self.path = path
        self.llm = Llama(
            model_path=path,
            n_ctx=n_ctx,  # Context window size
            n_gpu_layers=n_gpu_layers  # Number of layers to offload to GPU (-1 for all)
        )

    def prompt_local(self, system_prompt: str, user_prompt: str) -> dict:
        """
        Sends the prompt to the local model installed with llama-cpp at the self.path when the object was created.
        :param system_prompt: The system prompt text. The LLM is told that the system should operate with
        this prompt.
        :param user_prompt: The user prompt text. The LLM is told that the user should operate with
        this prompt.
        :return: The json returned from the LLM, as a python dictionary.
        """
        prompt = ("STRUCTURE THE OUTPUT THE EXACT SAME WAY AS THE INPUT WITH [System], [User], AND [Assistant]"
                  "where Assistant is YOUR message.\n"
                  "[System]\n") + system_prompt + "\n[User]\n" + user_prompt + "[Assistant]"
        start = time.perf_counter()
        response = self.llm(prompt)
        end = time.perf_counter()
        text = response["message"]["content"]
        wrapped = {
            "model": "llama-cpp",
            "created_at": datetime.now().isoformat(),
            "message": {
                "role": "assistant",
                "content": text,
            },
            "done": True,
            "time_stamp": round(end - start, 3)
        }
        return wrapped

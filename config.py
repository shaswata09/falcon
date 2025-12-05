from pathlib import Path


# Define the base directory for the project
def get_config(model_name: str) -> dict:
    model_config_dict = {
        "transformer": {
            "batch_size": 8,
            "num_epochs": 20,
            "lr": 10**-4,
            "seq_len": 4096,
            "d_model": 4096,
            "model_folder": "weights",
            "model_basename": "tmodel_",
            "preload": "latest",
            "tokenizer_file": "tokenizer_{0}.json",
            "experiment_name": "runs/graid/tmodel",
        }
    }

    # Return empty dict if model not found
    return model_config_dict.get(model_name, {})

import os
import gc
import pickle
import torch
from torch import nn
from transformers import AutoTokenizer, AutoModel
from tqdm import tqdm
import matplotlib.pyplot as plt
import seaborn as sns
import statistics


# Config
project_base_path = os.getcwd()
FINE_TUNED_MODEL_NAME = "all-mpnet-base-v2"
MODEL_NAME = f"/data/common/models/sentence-transformers/{FINE_TUNED_MODEL_NAME}"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
RUN = 2
###########################
MAX_LEN = 512
FINE_TUNED_MODEL_STATE_NAME = f"contrastive_encoder_r{RUN}.pt"
SEED = 42
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

MODEL_LOAD_PATH = os.path.join(
    project_base_path,
    f"script/fine_tuning/bi-encoder/snort/{FINE_TUNED_MODEL_NAME}/{FINE_TUNED_MODEL_STATE_NAME}",
)


# Bi-Encoder Model
class SentenceEncoder(nn.Module):
    def __init__(self, model_name):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_name)

    def forward(self, input_ids, attention_mask):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        embeddings = outputs.last_hidden_state[:, 0]  # CLS token
        return nn.functional.normalize(
            embeddings, p=2, dim=1
        )  # Normalize for cosine similarity


def snort_semantic_evaluator(
    rule: str, relevant_rules: list, threshold: float = 0.0, model=None, tokenizer=None
) -> dict:
    """
    Validate the semantic correctness of a Snort rule using a fine-tuned bi-encoder model w.r.t. relevant rules.

    Args:
        rule (str): The Snort rule to be checked.
        relevant_rules (list): A list of relevant Snort rules for comparison.
        model (nn.Module, optional): Pre-loaded bi-encoder model. If None, the model will be loaded inside the function.
        tokenizer (AutoTokenizer, optional): Pre-loaded tokenizer. If None, the tokenizer will be loaded inside the function.

    Returns:
        float: Semantic similarity score between 0 and 1.
    """

    if model is None or tokenizer is None:
        # Load tokenizer and model
        # Load tokenizer
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

        # Load model
        model = SentenceEncoder(MODEL_NAME).to(DEVICE)
        model.load_state_dict(torch.load(MODEL_LOAD_PATH, map_location=DEVICE))
        print(f"Loaded fine-tuned model from {MODEL_LOAD_PATH}")
        model.eval()

    tokenized_rule = tokenizer(
        rule, return_tensors="pt", padding=True, max_length=MAX_LEN, truncation=True
    )
    tokenized_relevant_rules = tokenizer(
        relevant_rules,
        return_tensors="pt",
        padding=True,
        max_length=MAX_LEN,
        truncation=True,
    )

    input_ids_tokenized_rule = tokenized_rule["input_ids"].to(DEVICE)
    attention_mask_tokenized_rule = tokenized_rule["attention_mask"].to(DEVICE)
    input_ids_tokenized_relevant_rules = tokenized_relevant_rules["input_ids"].to(
        DEVICE
    )
    attention_mask_tokenized_relevant_rules = tokenized_relevant_rules[
        "attention_mask"
    ].to(DEVICE)

    emb_tokenized_rule = model(input_ids_tokenized_rule, attention_mask_tokenized_rule)
    emb_tokenized_relevant_rules = model(
        input_ids_tokenized_relevant_rules, attention_mask_tokenized_relevant_rules
    )

    dot_product_matrix = torch.matmul(
        emb_tokenized_rule, emb_tokenized_relevant_rules.T
    )

    similarity_scores = dot_product_matrix[0]

    out_dict = {
        "rule": rule,
        "scores": similarity_scores.cpu().tolist(),
        "status": similarity_scores.max().item() >= threshold,
    }

    return out_dict


def get_relevant_rules_semantic_scores_for_input_cti(
    input_cti: str, relevant_rules_list: list, model=None, tokenizer=None
) -> dict:
    """
    __Summary__
    Get relevant rules from dummy snort dict based on semantic similarity scores.
    __Args__
        input_cti: The input CTI
        relevant_rules_list: The relevant rules list
        model: The fine-tuned bi-encoder model
        tokenizer: The tokenizer
    __Returns__
    dict: Score dictionary with relevant rules and their scores
    """

    if model is None or tokenizer is None:
        # Load tokenizer and model
        # Load tokenizer
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

        # Load model
        model = SentenceEncoder(MODEL_NAME).to(DEVICE)
        model.load_state_dict(torch.load(MODEL_LOAD_PATH, map_location=DEVICE))
        print(f"Loaded fine-tuned model from {MODEL_LOAD_PATH}")
        model.eval()

    scores_dict = snort_semantic_evaluator(
        input_cti, relevant_rules_list, model=model, tokenizer=tokenizer
    )

    return scores_dict["scores"]


if __name__ == "__main__":

    print("\n" + "=" * 50 + "\n")
    print("Test Case 1: Snort Semantic Validator\n")
    # Test Case 1: Rule vs Relevant Rules
    # Example usage for rule vs relevant rules
    test_rule = 'alert tcp any any -> any 80 (msg:"Test rule"; sid:1000001;)'
    relevant_rules = [
        'alert tcp any any -> any 80 (msg:"Test rule"; sid:1000001;)',
        'alert tcp any any -> any 80 (msg:"Test rule 1"; sid:1000002;)',
        'alert tcp any any -> any 443 (msg:"Test rule 2"; sid:1000003;)',
    ]
    scores = snort_semantic_evaluator(test_rule, relevant_rules)
    print("Semantic Similarity Scores:", scores)

    # Test Case 2: Rule vs CTI
    # Example usage for rule vs cti
    print("\n" + "=" * 50 + "\n")
    print("Test Case 2: Snort Semantic Validator\n")

    test_rule = 'alert tcp any any -> any 80 (msg:"Test rule"; sid:1000001;)'
    test_cti = """
        Title: Generic HTTP Traffic Detection on Port 80

        Threat Category: Network Traffic Monitoring – Informational

        Threat Name: HTTP Traffic Detection

        Detection Summary:
        This signature is designed to detect generic TCP traffic directed to port 80, which is the standard port for HTTP (Hypertext Transfer Protocol) communications. This rule serves as a basic monitoring mechanism to log or alert on HTTP traffic flowing through the network. It monitors all TCP connections regardless of source or destination, making it suitable for broad network visibility or baseline traffic analysis.

        Rule Metadata:
        Classification: Network Traffic
        Ruleset: Custom/Testing
        Priority: Informational

        Rule Logic Breakdown:
        Alert Type: alert

        Protocol: tcp

        Source IP: any (monitors traffic from any source IP address)

        Source Port: any (monitors traffic from any source port)

        Destination IP: any (monitors traffic to any destination IP address)

        Destination Port: 80 (standard HTTP port)

        Flow: Not specified (monitors all TCP traffic to port 80 regardless of flow state)

        Content Match: None specified (no payload inspection)

        Message: "Test rule"

        Technical Details:
        Port 80 is the standard well-known port for HTTP protocol communications. This rule does not perform deep packet inspection or content matching, making it a lightweight detection mechanism suitable for:
        - Network traffic baseline monitoring
        - HTTP service availability detection
        - Traffic volume analysis
        - Testing and validation of IDS/IPS functionality

        The absence of flow state requirements means this rule will trigger on any TCP packets destined for port 80, including SYN packets, established connections, and other TCP states.

        Indicators of Compromise (IOCs):
        Protocol: TCP
        Destination Port: 80/tcp

        Use Cases:
        1. Network traffic monitoring and logging
        2. Baseline establishment for normal HTTP traffic patterns
        3. IDS/IPS rule testing and validation
        4. Service availability monitoring
        5. Traffic volume analysis for capacity planning

        Recommended Actions:
        - Review triggered alerts to understand HTTP traffic patterns
        - Correlate with other security events for comprehensive analysis
        - Consider adding content matching for specific threat detection
        - Tune rule based on network environment to reduce false positives
        - Use as foundation for more specific HTTP-based threat detection rules

        Notes:
        This is a broad detection rule that may generate high volumes of alerts in production environments. It is recommended to:
        - Use in testing/development environments
        - Refine with additional constraints (source/destination networks, content matches)
        - Implement with appropriate alert thresholds and aggregation
        - Consider rate limiting or sampling for production deployment
        """
    scores = snort_semantic_evaluator(test_rule, [test_cti])
    print("Semantic Similarity Score (Rule vs CTI):", scores)

    # Test Case 3: Rule vs CTI with Threshold
    # Example usage for rule vs cti
    print("\n" + "=" * 50 + "\n")
    print("Test Case 3: Snort Semantic Validator with Threshold\n")

    test_rule = 'alert tcp any any -> any 80 (msg:"Test rule"; sid:1000001;)'
    test_cti = """
        Title: Generic HTTP Traffic Detection on Port 80

        Threat Category: Network Traffic Monitoring – Informational

        Threat Name: HTTP Traffic Detection

        Detection Summary:
        This signature is designed to detect generic TCP traffic directed to port 80, which is the standard port for HTTP (Hypertext Transfer Protocol) communications. This rule serves as a basic monitoring mechanism to log or alert on HTTP traffic flowing through the network. It monitors all TCP connections regardless of source or destination, making it suitable for broad network visibility or baseline traffic analysis.

        Rule Metadata:
        Classification: Network Traffic
        Ruleset: Custom/Testing
        Priority: Informational

        Rule Logic Breakdown:
        Alert Type: alert

        Protocol: tcp

        Source IP: any (monitors traffic from any source IP address)

        Source Port: any (monitors traffic from any source port)

        Destination IP: any (monitors traffic to any destination IP address)

        Destination Port: 80 (standard HTTP port)

        Flow: Not specified (monitors all TCP traffic to port 80 regardless of flow state)

        Content Match: None specified (no payload inspection)

        Message: "Test rule"

        Technical Details:
        Port 80 is the standard well-known port for HTTP protocol communications. This rule does not perform deep packet inspection or content matching, making it a lightweight detection mechanism suitable for:
        - Network traffic baseline monitoring
        - HTTP service availability detection
        - Traffic volume analysis
        - Testing and validation of IDS/IPS functionality

        The absence of flow state requirements means this rule will trigger on any TCP packets destined for port 80, including SYN packets, established connections, and other TCP states.

        Indicators of Compromise (IOCs):
        Protocol: TCP
        Destination Port: 80/tcp

        Use Cases:
        1. Network traffic monitoring and logging
        2. Baseline establishment for normal HTTP traffic patterns
        3. IDS/IPS rule testing and validation
        4. Service availability monitoring
        5. Traffic volume analysis for capacity planning

        Recommended Actions:
        - Review triggered alerts to understand HTTP traffic patterns
        - Correlate with other security events for comprehensive analysis
        - Consider adding content matching for specific threat detection
        - Tune rule based on network environment to reduce false positives
        - Use as foundation for more specific HTTP-based threat detection rules

        Notes:
        This is a broad detection rule that may generate high volumes of alerts in production environments. It is recommended to:
        - Use in testing/development environments
        - Refine with additional constraints (source/destination networks, content matches)
        - Implement with appropriate alert thresholds and aggregation
        - Consider rate limiting or sampling for production deployment
        """
    scores = snort_semantic_evaluator(test_rule, [test_cti], threshold=0.95)
    print("Semantic Similarity Score (Rule vs CTI) with threshold 0.95:", scores)

    # Test Case 4: Rule vs Relevant Rules only scores
    print("\n" + "=" * 50 + "\n")
    print("Test Case 4: Get Relevant Rules Semantic Scores for Input CTI\n")

    test_cti = """
        Title: Generic HTTP Traffic Detection on Port 80

        Threat Category: Network Traffic Monitoring – Informational

        Threat Name: HTTP Traffic Detection

        Detection Summary:
        This signature is designed to detect generic TCP traffic directed to port 80, which is the standard port for HTTP (Hypertext Transfer Protocol) communications. This rule serves as a basic monitoring mechanism to log or alert on HTTP traffic flowing through the network. It monitors all TCP connections regardless of source or destination, making it suitable for broad network visibility or baseline traffic analysis.

        Rule Metadata:
        Classification: Network Traffic
        Ruleset: Custom/Testing
        Priority: Informational

        Rule Logic Breakdown:
        Alert Type: alert

        Protocol: tcp

        Source IP: any (monitors traffic from any source IP address)

        Source Port: any (monitors traffic from any source port)

        Destination IP: any (monitors traffic to any destination IP address)

        Destination Port: 80 (standard HTTP port)

        Flow: Not specified (monitors all TCP traffic to port 80 regardless of flow state)

        Content Match: None specified (no payload inspection)

        Message: "Test rule"

        Technical Details:
        Port 80 is the standard well-known port for HTTP protocol communications. This rule does not perform deep packet inspection or content matching, making it a lightweight detection mechanism suitable for:
        - Network traffic baseline monitoring
        - HTTP service availability detection
        - Traffic volume analysis
        - Testing and validation of IDS/IPS functionality

        The absence of flow state requirements means this rule will trigger on any TCP packets destined for port 80, including SYN packets, established connections, and other TCP states.

        Indicators of Compromise (IOCs):
        Protocol: TCP
        Destination Port: 80/tcp

        Use Cases:
        1. Network traffic monitoring and logging
        2. Baseline establishment for normal HTTP traffic patterns
        3. IDS/IPS rule testing and validation
        4. Service availability monitoring
        5. Traffic volume analysis for capacity planning

        Recommended Actions:
        - Review triggered alerts to understand HTTP traffic patterns
        - Correlate with other security events for comprehensive analysis
        - Consider adding content matching for specific threat detection
        - Tune rule based on network environment to reduce false positives
        - Use as foundation for more specific HTTP-based threat detection rules

        Notes:
        This is a broad detection rule that may generate high volumes of alerts in production environments. It is recommended to:
        - Use in testing/development environments
        - Refine with additional constraints (source/destination networks, content matches)
        - Implement with appropriate alert thresholds and aggregation
        - Consider rate limiting or sampling for production deployment
        """
    relevant_rules = [
        'alert tcp any any -> any 80 (msg:"Test rule 1"; sid:1000002;)',
        'alert tcp any any -> any 443 (msg:"Test rule 2"; sid:1000003;)',
        'alert tcp any any -> any 80 (msg:"Test rule"; sid:1000001;)',
    ]
    scores = get_relevant_rules_semantic_scores_for_input_cti(test_cti, relevant_rules)
    print("Semantic Similarity Scores for CTI vs Relevant Rules:", scores)
    print(f"Max Score: {max(scores)}")

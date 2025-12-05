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
    f"script/fine_tuning/bi-encoder/yara/{FINE_TUNED_MODEL_NAME}/{FINE_TUNED_MODEL_STATE_NAME}",
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


def yara_semantic_evaluator(
    rule: str, relevant_rules: list, threshold: float = 0.0, model=None, tokenizer=None
) -> dict:
    """
    Validate the semantic correctness of a yara rule using a fine-tuned bi-encoder model w.r.t. relevant rules.

    Args:
        rule (str): The yara rule to be checked.
        relevant_rules (list): A list of relevant yara rules for comparison.
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
    Get relevant rules from dummy yara dict based on semantic similarity scores.
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

    scores_dict = yara_semantic_evaluator(
        input_cti, relevant_rules_list, model=model, tokenizer=tokenizer
    )

    return scores_dict["scores"]


if __name__ == "__main__":

    print("\n" + "=" * 50 + "\n")
    print("Test Case 1: YARA Semantic Validator\n")
    # Test Case 1: Rule vs Relevant Rules
    # Example usage for rule vs relevant rules
    test_rule = """
        rule SuspiciousPowerShell {
            meta:
                description = "Detects suspicious PowerShell commands"
                author = "Security Team"
            strings:
                $cmd1 = "powershell" nocase
                $cmd2 = "Invoke-Expression" nocase
                $cmd3 = "downloadstring" nocase
            condition:
                $cmd1 and ($cmd2 or $cmd3)
        }
        """
    relevant_rules = [
        """rule PowerShellDownload {
            strings:
                $s1 = "powershell" nocase
                $s2 = "downloadfile" nocase
            condition:
                all of them
        }""",
        """rule MaliciousScript {
            strings:
                $s1 = "Invoke-Expression"
                $s2 = "Net.WebClient"
            condition:
                all of them
        }""",
        """rule WebRequest {
            strings:
                $s1 = "System.Net.WebClient"
                $s2 = "DownloadString"
            condition:
                all of them
        }""",
        """rule SuspiciousPowerShell {
            meta:
                description = "Detects suspicious PowerShell commands"
                author = "Security Team"
            strings:
                $cmd1 = "powershell" nocase
                $cmd2 = "Invoke-Expression" nocase
                $cmd3 = "downloadstring" nocase
            condition:
                $cmd1 and ($cmd2 or $cmd3)
        }
    """,
    ]
    scores = yara_semantic_evaluator(test_rule, relevant_rules)
    print("Semantic Similarity Scores:", scores)

    # Test Case 2: Rule vs CTI
    # Example usage for rule vs cti
    print("\n" + "=" * 50 + "\n")
    print("Test Case 2: YARA Semantic Validator\n")

    test_rule = """
        rule PowerShellMalware {
            meta:
                description = "Detects PowerShell-based malware"
                threat_level = "High"
            strings:
                $ps = "powershell.exe" nocase
                $download = "downloadstring" nocase
                $invoke = "Invoke-Expression" nocase
            condition:
                $ps and ($download or $invoke)
        }
        """
    test_cti = """
        Title: Detection of PowerShell-Based Malware Download Activity

        Threat Category: Malware – Command & Control

        Threat Name: PowerShell Malware Downloader

        Detection Summary:
        This signature is designed to detect malicious PowerShell activity commonly used by threat actors to download and execute malicious payloads. The malware exhibits characteristic behavior by using PowerShell's built-in web client capabilities to download files or scripts from remote servers and execute them directly in memory using Invoke-Expression cmdlets. This technique is frequently observed in fileless malware attacks and command-and-control communications.

        Rule Metadata:
        Classification: Malicious Activity
        Ruleset: Malware Detection
        Threat Level: High
        Priority: Critical

        Rule Logic Breakdown:
        Detection Type: File/Process Analysis

        Target Process: powershell.exe

        String Patterns:
        - "powershell.exe" (case insensitive) - Identifies PowerShell execution
        - "downloadstring" (case insensitive) - Detects file download operations
        - "Invoke-Expression" (case insensitive) - Identifies code execution attempts

        Condition Logic: Process must be PowerShell AND contain either download or execution patterns

        Technical Details:
        PowerShell is a legitimate Windows administration tool that threat actors frequently abuse for malicious purposes. The downloadstring method from System.Net.WebClient class is commonly used to fetch remote content, while Invoke-Expression (or its alias IEX) executes strings as PowerShell commands. This combination indicates potential malware download and execution activity.

        The detection focuses on identifying the simultaneous presence of PowerShell process execution with suspicious network download and code execution patterns, which strongly suggests malicious intent rather than legitimate administrative activity.

        Indicators of Compromise (IOCs):
        - Process Name: powershell.exe
        - Command Pattern: downloadstring
        - Command Pattern: Invoke-Expression (IEX)
        - Behavior: Remote file download with immediate execution

        Common Attack Vectors:
        1. Phishing emails with malicious PowerShell scripts
        2. Drive-by downloads triggering PowerShell execution
        3. Compromised websites serving PowerShell payloads
        4. Lateral movement using PowerShell remoting
        5. Persistence mechanisms via scheduled tasks running PowerShell

        Recommended Actions:
        - Immediately isolate affected systems from the network
        - Terminate suspicious PowerShell processes
        - Analyze PowerShell command history and logs
        - Check for persistence mechanisms (scheduled tasks, registry run keys)
        - Perform memory analysis to identify injected code
        - Block network connections to suspicious remote servers
        - Update endpoint protection signatures
        - Implement PowerShell logging and transcription
        - Apply least privilege principles to PowerShell execution policies

        Prevention Measures:
        - Enable PowerShell logging (Script Block Logging, Module Logging)
        - Implement application whitelisting to control script execution
        - Configure PowerShell Constrained Language Mode
        - Monitor and restrict PowerShell remote execution capabilities
        - Deploy endpoint detection and response (EDR) solutions
        - Educate users about phishing and social engineering tactics

        Notes:
        This detection pattern may generate false positives in environments where administrators regularly use PowerShell for legitimate automation tasks. Consider implementing exclusions for known administrative accounts and scripts, while maintaining strict monitoring of all PowerShell execution activity.
        """

    scores = yara_semantic_evaluator(test_rule, [test_cti])
    print("Semantic Similarity Score (Rule vs CTI):", scores)

    # Test Case 3: Rule vs CTI with Threshold
    # Example usage for rule vs cti
    print("\n" + "=" * 50 + "\n")
    print("Test Case 3: YARA Semantic Validator with Threshold\n")

    test_rule = """
        rule RansomwareEncryption {
            meta:
                description = "Detects ransomware file encryption behavior"
                author = "Threat Intel Team"
            strings:
                $enc1 = "AES" nocase
                $enc2 = "RSA" nocase
                $ext1 = ".locked"
                $ext2 = ".encrypted"
                $msg = "Your files have been encrypted"
            condition:
                ($enc1 or $enc2) and ($ext1 or $ext2 or $msg)
        }
        """

    test_cti = """
        Title: Detection of Ransomware File Encryption Activity

        Threat Category: Malware – Ransomware

        Threat Name: Generic Ransomware Encryptor

        Detection Summary:
        This signature identifies ransomware behavior characterized by file encryption operations using strong cryptographic algorithms. The malware typically employs AES or RSA encryption to render victim files inaccessible, appending distinctive file extensions such as .locked or .encrypted. Additionally, the presence of ransom messages indicating file encryption is a strong indicator of ransomware activity.

        Rule Metadata:
        Classification: Ransomware Activity
        Ruleset: Malware Detection
        Threat Level: Critical
        Priority: Urgent

        Rule Logic Breakdown:
        Detection Type: File/Memory Analysis

        Encryption Indicators:
        - "AES" (case insensitive) - Advanced Encryption Standard usage
        - "RSA" (case insensitive) - RSA public key cryptography usage

        File Extension Patterns:
        - ".locked" - Common ransomware file extension
        - ".encrypted" - Common ransomware file extension

        Message Patterns:
        - "Your files have been encrypted" - Typical ransom message text

        Condition Logic: Must detect encryption algorithm (AES OR RSA) AND at least one ransomware indicator (file extension OR ransom message)

        Technical Details:
        Ransomware families frequently use combination encryption schemes, employing symmetric algorithms like AES for file encryption speed and asymmetric algorithms like RSA for key protection. The modified file extensions serve as visual indicators of encrypted files, while ransom messages inform victims of the attack and demand payment.

        This detection pattern identifies the core behavioral characteristics common across multiple ransomware variants, focusing on cryptographic operations and file modification patterns rather than specific malware signatures.

        Indicators of Compromise (IOCs):
        - Encryption Algorithm Usage: AES, RSA
        - File Extensions: .locked, .encrypted, .crypted
        - Ransom Note Strings: "Your files have been encrypted"
        - Behavior: Mass file encryption, file extension changes

        Recommended Actions:
        - Immediately isolate infected systems from network
        - Do NOT pay the ransom
        - Identify patient zero and attack vector
        - Restore files from clean backups
        - Analyze malware sample for decryption possibilities
        - Check for available decryption tools
        - Report to law enforcement and CERT
        - Implement network segmentation to prevent spread
        - Update all security software and signatures
        - Conduct forensic analysis to identify persistence mechanisms

        Prevention Measures:
        - Maintain regular, tested backups (offline/air-gapped)
        - Implement backup versioning and retention policies
        - Use application whitelisting to prevent unauthorized executables
        - Enable Protected Folders feature in Windows Defender
        - Deploy EDR solutions with behavioral monitoring
        - Segment networks to limit ransomware spread
        - Keep all systems and software updated
        - Train users on phishing and social engineering awareness
        """
    scores = yara_semantic_evaluator(test_rule, [test_cti], threshold=0.95)
    print("Semantic Similarity Score (Rule vs CTI) with Threshold:", scores)
    print(f"Status: {'PASS' if scores['status'] else 'FAIL'}")

    # Test Case 4: Get Relevant Rules Semantic Scores for Input CTI
    print("\n" + "=" * 50 + "\n")
    print("Test Case 4: Get Relevant Rules Semantic Scores for Input CTI\n")

    test_cti = """
        Title: Detection of Credential Harvesting Activity

        Threat Category: Malware – Information Stealer

        Threat Name: Credential Stealer

        Detection Summary:
        This signature detects malicious software designed to harvest user credentials from various sources including web browsers, email clients, and system credential stores. The malware typically searches for common credential storage locations, accesses browser profile databases, and attempts to extract saved passwords, cookies, and authentication tokens.

        Rule Metadata:
        Classification: Information Theft
        Ruleset: Credential Access
        Threat Level: High
        Priority: Critical

        Rule Logic Breakdown:
        Detection Type: File/Memory/Registry Analysis

        Target Locations:
        - Browser credential stores (Chrome, Firefox, Edge)
        - Windows Credential Manager
        - Email client credential storage
        - FTP client saved sessions

        String Patterns:
        - "Login Data" - Chrome credentials database
        - "key3.db" - Firefox password database
        - "Credential Manager" - Windows credential store
        - Browser profile paths

        Behavioral Indicators:
        - Access to browser profile directories
        - Reading credential database files
        - Registry key access for stored credentials
        - Network exfiltration of credential data

        Technical Details:
        Credential stealing malware operates by targeting known locations where applications store authentication credentials. Modern browsers encrypt stored passwords, but malware can often access the master key through memory or registry manipulation. The malware typically enumerates all user profiles, accesses credential databases, decrypts stored passwords, and exfiltrates the data to command-and-control servers.

        Indicators of Compromise (IOCs):
        - File Access: Login Data, key3.db, Credentials
        - Registry Access: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
        - Process Behavior: Suspicious access to browser profile directories
        - Network Activity: Exfiltration to external IPs

        Recommended Actions:
        - Change all potentially compromised passwords immediately
        - Enable multi-factor authentication on all accounts
        - Scan systems with updated antivirus software
        - Monitor for unauthorized account access
        - Review browser extensions and remove suspicious ones
        - Clear browser saved passwords
        - Check for unauthorized changes to accounts
        - Implement credential guard on Windows systems
        """

    relevant_rules = [
        """rule BrowserCredentialAccess {
    strings:
        $s1 = "Login Data"
        $s2 = "Cookies"
        $s3 = "Web Data"
    condition:
        2 of them
}""",
        """rule PasswordStealer {
    strings:
        $s1 = "key3.db"
        $s2 = "logins.json"
        $s3 = "password"
    condition:
        any of them
}""",
        """rule CredentialManager {
    strings:
        $s1 = "Credential Manager"
        $s2 = "CredEnumerate"
        $s3 = "vault"
    condition:
        all of them
}""",
    ]
    scores = get_relevant_rules_semantic_scores_for_input_cti(test_cti, relevant_rules)
    print("Semantic Similarity Scores for CTI vs Relevant Rules:", scores)
    print(f"Max Score: {max(scores)}")

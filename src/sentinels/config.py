# src/sentinels/config.py
import os
from typing import Any
from dotenv import load_dotenv
from agent_framework.openai import OpenAIChatClient
from agent_framework.ollama import OllamaChatClient

load_dotenv()


def get_chat_client() -> Any:
    """
    Factory function returning the configured MAF chat client.
    Supports:
      - 'ollama' (local LLM via Ollama server, e.g. llama3.2, qwen2.5-coder)
      - 'azure'  (Azure OpenAI reasoning/chat models)
      - 'openai' (standard direct OpenAI API, e.g. gpt-4o-mini)
    Provider is selected via LLM_PROVIDER or auto-detected from environment variables.
    """
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()

    # Auto-detection if LLM_PROVIDER is not explicitly specified
    if not provider:
        if os.getenv("AZURE_OPENAI_ENDPOINT") and os.getenv("AZURE_OPENAI_API_KEY"):
            provider = "azure"
        elif os.getenv("OLLAMA_MODEL"):
            provider = "ollama"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        else:
            # Default to local Ollama if no cloud keys configured
            provider = "ollama"

    if provider == "ollama":
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama3.2")
        return OllamaChatClient(model=model, host=host)

    elif provider == "azure":
        return get_azure_chat_client()

    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("Missing OPENAI_API_KEY environment variable for 'openai' provider.")
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return OpenAIChatClient(model=model, api_key=api_key)

    else:
        raise ValueError(
            f"Unsupported LLM_PROVIDER '{provider}'. Supported providers are: 'ollama', 'azure', 'openai'."
        )


def get_azure_chat_client() -> OpenAIChatClient:
    """
    Creates an Azure OpenAI chat client for Microsoft Agent Framework.
    Uses the OpenAI Responses API via OpenAIChatClient.
    """
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    api_key = os.getenv("AZURE_OPENAI_API_KEY")

    # Note: In Azure, this is your DEPLOYMENT name, not necessarily the model name.
    # E.g., you might deploy 'gpt-4o-mini' under the name 'sentinel-gpt'.
    deployment_name = os.getenv("AZURE_OPENAI_GPT_DEPLOYMENT", "gpt-5.4-mini")

    # Let the SDK pick its own default ("preview", the rolling latest-preview
    # alias) unless the caller pins one -- a hardcoded pinned version here
    # previously shadowed the SDK's default and broke newer reasoning-model
    # deployments (e.g. gpt-5-mini) that need the Responses API.
    api_version = os.getenv("AZURE_OPENAI_API_VERSION") or None

    if not endpoint:
        raise ValueError("Missing AZURE_OPENAI_ENDPOINT environment variable.")
    if not api_key:
        raise ValueError("Missing AZURE_OPENAI_API_KEY environment variable.")

    # Initialize and return the MAF OpenAIChatClient configured for Azure
    return OpenAIChatClient(
        model=deployment_name,
        azure_endpoint=endpoint,
        api_key=api_key,
        api_version=api_version,
    )


def get_active_provider_info() -> dict:
    """Returns detected active provider name, model, and endpoint details."""
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if not provider:
        if os.getenv("AZURE_OPENAI_ENDPOINT") and os.getenv("AZURE_OPENAI_API_KEY"):
            provider = "azure"
        elif os.getenv("OLLAMA_MODEL"):
            provider = "ollama"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        else:
            provider = "ollama"

    if provider == "azure":
        model = os.getenv("AZURE_OPENAI_GPT_DEPLOYMENT", "gpt-5-mini")
        return {
            "provider": "azure",
            "display": "AZURE OPENAI",
            "model": model,
            "endpoint": os.getenv("AZURE_OPENAI_ENDPOINT", "Configured")
        }
    elif provider == "openai":
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return {
            "provider": "openai",
            "display": "OPENAI",
            "model": model,
            "endpoint": "https://api.openai.com/v1"
        }
    else:
        model = os.getenv("OLLAMA_MODEL", "llama3.2")
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        return {
            "provider": "ollama",
            "display": "OLLAMA",
            "model": model,
            "endpoint": host
        }
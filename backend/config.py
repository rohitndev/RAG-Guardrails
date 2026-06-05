"""
Configuration settings for the RAG Guardrails application.
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
FAISS_DIR = DATA_DIR / "faiss_index"
LOGS_DIR = DATA_DIR / "logs"

# Create directories if they don't exist
for dir_path in [UPLOADS_DIR, FAISS_DIR, LOGS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Ollama settings
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:8b")

# Embedding model settings
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384  # Dimension for all-MiniLM-L6-v2

# Document processing settings
CHUNK_SIZE = 500  # characters
CHUNK_OVERLAP = 50  # characters
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Retrieval settings
TOP_K_RESULTS = 10
SIMILARITY_THRESHOLD = 0.3

# Guardrail settings
TRUST_SCORE_THRESHOLD = 0.6
MAX_CONTEXT_LENGTH = 2000  # characters for low trust
MAX_CONTEXT_LENGTH_HIGH_TRUST = 4000  # characters for high trust

# ---------------------------------------------------------------------------
# Advanced guardrail settings (v2)
# ---------------------------------------------------------------------------

# Threat-fusion decision thresholds. The fused score combines the regex,
# semantic and (optional) LLM-judge layers into a single 0..1 risk score.
FUSION_BLOCK_THRESHOLD = float(os.getenv("FUSION_BLOCK_THRESHOLD", "0.75"))
FUSION_WARN_THRESHOLD = float(os.getenv("FUSION_WARN_THRESHOLD", "0.45"))

# Semantic guard: embedding-similarity detection of paraphrased attacks.
# Reuses the already-loaded sentence-transformers model (no extra dependency).
SEMANTIC_GUARD_ENABLED = os.getenv("SEMANTIC_GUARD_ENABLED", "true").lower() == "true"
SEMANTIC_BLOCK_SIMILARITY = float(os.getenv("SEMANTIC_BLOCK_SIMILARITY", "0.62"))
SEMANTIC_WARN_SIMILARITY = float(os.getenv("SEMANTIC_WARN_SIMILARITY", "0.45"))

# LLM-as-judge: escalate ambiguous ("gray zone") inputs to the local LLM for a
# semantic verdict. Disabled by default because it adds an extra inference call.
LLM_JUDGE_ENABLED = os.getenv("LLM_JUDGE_ENABLED", "false").lower() == "true"
# Only call the judge when the fused score is inside this uncertain band.
LLM_JUDGE_GRAY_LOW = float(os.getenv("LLM_JUDGE_GRAY_LOW", "0.35"))
LLM_JUDGE_GRAY_HIGH = float(os.getenv("LLM_JUDGE_GRAY_HIGH", "0.80"))
LLM_JUDGE_TIMEOUT = int(os.getenv("LLM_JUDGE_TIMEOUT", "20"))  # seconds

# Canary / prompt-leak detection: a secret token is embedded in the locked
# system prompt; if it ever appears in the model output the prompt was leaked.
CANARY_ENABLED = os.getenv("CANARY_ENABLED", "true").lower() == "true"

# Optional Microsoft Presidio PII engine. Falls back to regex if unavailable.
PRESIDIO_ENABLED = os.getenv("PRESIDIO_ENABLED", "false").lower() == "true"

# Allowed file extensions
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".md"}

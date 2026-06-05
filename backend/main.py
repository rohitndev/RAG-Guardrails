"""
FastAPI application for RAG Guardrails demonstration.
"""
import os
import sys
from pathlib import Path
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import UPLOADS_DIR, ALLOWED_EXTENSIONS, MAX_FILE_SIZE
from document_processing import DocumentParser, TextChunker, EmbeddingModel
from vector_store import FAISSVectorStore
from rag import RAGPipeline, OllamaLLM
from guardrails import (
    InputGuard, DocumentSanitizer, SystemPromptManager,
    TrustScorer, OutputGuard, SecurityLogger, GuardrailsManager
)


# Global instances
vector_store: FAISSVectorStore = None
embedding_model: EmbeddingModel = None
rag_pipeline: RAGPipeline = None
guardrails_manager: GuardrailsManager = None
security_logger: SecurityLogger = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize components on startup."""
    global vector_store, embedding_model, rag_pipeline, guardrails_manager, security_logger
    
    print("Initializing RAG Guardrails system...")
    
    # Initialize components
    vector_store = FAISSVectorStore()
    embedding_model = EmbeddingModel()
    llm = OllamaLLM()

    # Check Ollama connection
    if not llm.check_connection():
        print("WARNING: Ollama is not running. Please start Ollama to use the chat feature.")

    # Build the guardrails manager once so the semantic-guard seed embeddings and
    # the (optional) Presidio engine are initialised a single time at startup.
    guardrails_manager = GuardrailsManager(embedding_model=embedding_model, llm=llm)
    security_logger = guardrails_manager.logger
    rag_pipeline = RAGPipeline(vector_store, embedding_model, llm, guardrails_manager)
    
    print("RAG Guardrails system initialized successfully!")
    
    yield
    
    # Cleanup on shutdown
    print("Shutting down RAG Guardrails system...")


# Create FastAPI app
app = FastAPI(
    title="RAG Guardrails Demo",
    description="Demonstration of security differences between guarded and unguarded RAG systems",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response models
class ChatRequest(BaseModel):
    query: str
    guardrails: bool = True
    system_prompt: Optional[str] = None
    temperature: float = 0.7
    top_k: int = 5


class ChatResponse(BaseModel):
    answer: str
    sources: List[dict]
    guardrails_active: bool
    blocked: bool = False
    block_reason: Optional[str] = None
    guardrail_logs: List[dict] = []
    trace: List[dict] = []
    threat_level: float = 0.0


class UploadResponse(BaseModel):
    success: bool
    message: str
    filename: str
    chunks_created: int


class StatusResponse(BaseModel):
    ollama_connected: bool
    model_available: bool
    documents_count: int
    sources: List[str]
    capabilities: dict = {}


# API Endpoints

@app.get("/")
async def root():
    """Serve the frontend."""
    frontend_path = Path(__file__).parent.parent / "frontend" / "index.html"
    if frontend_path.exists():
        return FileResponse(frontend_path)
    return {"message": "RAG Guardrails API is running. Frontend not found."}


@app.get("/api/status")
async def get_status() -> StatusResponse:
    """Get system status."""
    llm = OllamaLLM()
    
    gm = guardrails_manager
    capabilities = {
        "regex_guard": True,
        "semantic_guard": bool(gm and getattr(gm.semantic_guard, "enabled", False)),
        "llm_judge": bool(gm and getattr(gm.threat_engine, "llm_judge_enabled", False)),
        "canary": bool(gm and getattr(gm.canary, "enabled", False)),
        "presidio_pii": bool(gm and getattr(gm.output_guard, "_presidio", None) is not None),
        "model": llm.model,
    }

    return StatusResponse(
        ollama_connected=llm.check_connection(),
        model_available=llm.check_model_available(),
        documents_count=vector_store.count if vector_store else 0,
        sources=vector_store.get_all_sources() if vector_store else [],
        capabilities=capabilities,
    )


@app.post("/api/upload")
async def upload_document(file: UploadFile = File(...)) -> UploadResponse:
    """
    Upload and process a document (PDF or TXT).
    """
    global vector_store, embedding_model
    
    # Validate file extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    # Read file content
    content = await file.read()
    
    # Check file size
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"
        )
    
    # Save file
    file_path = UPLOADS_DIR / file.filename
    with open(file_path, 'wb') as f:
        f.write(content)
    
    try:
        # Parse document
        parser = DocumentParser()
        text = parser.parse(file_path)
        text = parser.clean_text(text)
        
        if not text.strip():
            raise HTTPException(status_code=400, detail="Document appears to be empty")
        
        # Chunk document
        chunker = TextChunker()
        chunks = chunker.chunk(text, source_file=file.filename)
        
        if not chunks:
            raise HTTPException(status_code=400, detail="Could not create chunks from document")
        
        # Generate embeddings
        chunk_texts = [chunk.content for chunk in chunks]
        embeddings = embedding_model.embed_documents(chunk_texts)
        
        # Store in vector database
        chunk_indices = [chunk.chunk_index for chunk in chunks]
        vector_store.add_documents(
            contents=chunk_texts,
            embeddings=embeddings,
            source_file=file.filename,
            chunk_indices=chunk_indices
        )
        
        return UploadResponse(
            success=True,
            message=f"Document processed successfully",
            filename=file.filename,
            chunks_created=len(chunks)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing document: {str(e)}")


@app.post("/api/chat")
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Query the RAG system.
    """
    global rag_pipeline, security_logger
    
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    
    try:
        # Process query through RAG pipeline
        response = rag_pipeline.query(
            query=request.query,
            guardrails=request.guardrails,
            system_prompt=request.system_prompt,
            top_k=request.top_k,
            temperature=request.temperature
        )
        
        return ChatResponse(
            answer=response.answer,
            sources=response.sources,
            guardrails_active=response.guardrails_active,
            blocked=response.blocked,
            block_reason=response.block_reason,
            guardrail_logs=response.guardrail_logs or [],
            trace=response.trace or [],
            threat_level=response.threat_level,
        )
        
    except ConnectionError as e:
        raise HTTPException(
            status_code=503,
            detail="Could not connect to Ollama. Please ensure Ollama is running."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")


@app.get("/api/logs")
async def get_security_logs(
    event_type: Optional[str] = None,
    limit: int = 50
):
    """Get security event logs."""
    global security_logger
    
    if security_logger is None:
        return {"events": [], "summary": {}}
    
    events = security_logger.get_events(event_type=event_type, limit=limit)
    summary = security_logger.get_summary()
    
    return {
        "events": [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "input_preview": e.input_text[:100] + "..." if len(e.input_text) > 100 else e.input_text,
                "threat_level": e.threat_level,
                "action_taken": e.action_taken,
                "details": e.details
            }
            for e in events
        ],
        "summary": summary
    }


@app.get("/api/analytics")
async def get_analytics():
    """Aggregated security analytics for the dashboard."""
    global security_logger
    if security_logger is None:
        return {"kpis": {}, "events_by_type": {}, "events_by_category": {},
                "threat_histogram": {}, "timeline": [], "recent_high_threat": []}
    return security_logger.get_analytics()


@app.get("/dashboard")
async def dashboard():
    """Serve the security analytics dashboard."""
    dash_path = Path(__file__).parent.parent / "frontend" / "dashboard.html"
    if dash_path.exists():
        return FileResponse(dash_path)
    raise HTTPException(status_code=404, detail="Dashboard not found")


@app.delete("/api/documents")
async def clear_documents():
    """Clear all documents from the vector store."""
    global vector_store
    
    if vector_store:
        vector_store.clear()
    
    return {"success": True, "message": "All documents cleared"}


@app.delete("/api/logs")
async def clear_logs():
    """Clear security logs."""
    global security_logger
    
    if security_logger:
        security_logger.clear_events()
    
    return {"success": True, "message": "Security logs cleared"}


# Serve static files for frontend
frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/css", StaticFiles(directory=frontend_dir / "css"), name="css")
    app.mount("/js", StaticFiles(directory=frontend_dir / "js"), name="js")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)

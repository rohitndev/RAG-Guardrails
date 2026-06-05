"""
Document parser for extracting text from PDF and TXT files.
"""
import fitz  # PyMuPDF
import chardet
from pathlib import Path
from typing import Optional


class DocumentParser:
    """Parse PDF and TXT documents to extract text content."""
    
    @staticmethod
    def parse(file_path: Path) -> str:
        """
        Parse a document and extract its text content.
        
        Args:
            file_path: Path to the document file
            
        Returns:
            Extracted text content
            
        Raises:
            ValueError: If file type is not supported
        """
        suffix = file_path.suffix.lower()
        
        if suffix == ".pdf":
            return DocumentParser._parse_pdf(file_path)
        elif suffix in (".txt", ".md", ".markdown"):
            return DocumentParser._parse_txt(file_path)
        else:
            raise ValueError(f"Unsupported file type: {suffix}")
    
    @staticmethod
    def _parse_pdf(file_path: Path) -> str:
        """Extract text from a PDF file."""
        text_parts = []
        
        with fitz.open(file_path) as doc:
            for page in doc:
                text = page.get_text()
                if text.strip():
                    text_parts.append(text)
        
        return "\n\n".join(text_parts)
    
    @staticmethod
    def _parse_txt(file_path: Path) -> str:
        """Extract text from a TXT file with encoding detection."""
        # Read raw bytes to detect encoding
        raw_bytes = file_path.read_bytes()
        
        # Detect encoding
        detected = chardet.detect(raw_bytes)
        encoding = detected.get("encoding", "utf-8") or "utf-8"
        
        # Decode with detected encoding
        try:
            return raw_bytes.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            # Fallback to utf-8 with error handling
            return raw_bytes.decode("utf-8", errors="replace")
    
    @staticmethod
    def clean_text(text: str) -> str:
        """
        Clean extracted text by removing excessive whitespace.
        
        Args:
            text: Raw extracted text
            
        Returns:
            Cleaned text
        """
        # Replace multiple newlines with double newline
        import re
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        # Replace multiple spaces with single space
        text = re.sub(r' {2,}', ' ', text)
        
        # Strip leading/trailing whitespace from each line
        lines = [line.strip() for line in text.split('\n')]
        text = '\n'.join(lines)
        
        return text.strip()

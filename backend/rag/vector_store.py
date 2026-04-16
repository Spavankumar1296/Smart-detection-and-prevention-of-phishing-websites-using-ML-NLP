import os
import json

from langchain_core.documents import Document
from langchain_text_splitters import CharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
# ==============================
# PATH CONFIGURATION
# ==============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
RAG_STATIC_PATH = os.path.join(BASE_DIR, "rag_data", "static")
RAG_LIVE_PATH = os.path.join(BASE_DIR, "rag_data", "live")
FAISS_INDEX_PATH = os.path.join(os.path.dirname(__file__), "faiss_index")


# ==============================
# LOAD STATIC DOCUMENTS
# ==============================

def load_static_documents():
    documents = []

    for file_name in os.listdir(RAG_STATIC_PATH):
        file_path = os.path.join(RAG_STATIC_PATH, file_name)

        if file_name.endswith(".txt"):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                documents.append(Document(page_content=content))

    return documents


# ==============================
# LOAD LIVE DOCUMENTS (PhishTank)
# ==============================

def load_live_documents():
    documents = []

    phishtank_file = os.path.join(RAG_LIVE_PATH, "phishtank.json")

    if not os.path.exists(phishtank_file):
        print("[!] No PhishTank data found. Run threat_fetcher.py first.")
        return documents

    with open(phishtank_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data:
        documents.append(Document(page_content=item["text"]))

    return documents


# ==============================
# BUILD FAISS INDEX
# ==============================

def build_faiss_index():
    print("[*] Building FAISS index...")

    static_docs = load_static_documents()
    live_docs = load_live_documents()

    all_docs = static_docs + live_docs

    if not all_docs:
        print("[ERROR] No documents found to index.")
        return

    # Split large documents
    text_splitter = CharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50
    )

    split_docs = text_splitter.split_documents(all_docs)

    # Load embedding model
    embeddings = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2"
    )

    # Create FAISS index
    vectorstore = FAISS.from_documents(split_docs, embeddings)

    # Save locally
    vectorstore.save_local(FAISS_INDEX_PATH)

    print(f"[✓] FAISS index built successfully with {len(split_docs)} chunks.")


# ==============================
# LOAD FAISS INDEX
# ==============================

def load_faiss_index():
    embeddings = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2"
    )

    if not os.path.exists(FAISS_INDEX_PATH):
        print("[!] FAISS index not found. Building now...")
        build_faiss_index()

    return FAISS.load_local(FAISS_INDEX_PATH, embeddings, allow_dangerous_deserialization=True)

if __name__ == "__main__":
    build_faiss_index()
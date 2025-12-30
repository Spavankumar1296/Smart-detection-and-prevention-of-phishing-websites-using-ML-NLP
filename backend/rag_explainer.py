import json
import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

class RAGExplainer:
    def __init__(self, kb_path='backend/phishing_kb.json'):
        self.kb_path = kb_path
        self.kb_data = []
        self.index = None
        self.model = None
        
        # Load KB
        if os.path.exists(kb_path):
            with open(kb_path, 'r') as f:
                self.kb_data = json.load(f)
        else:
            print(f"Warning: KB not found at {kb_path}")

        # Initialize Model and Index
        # Using a small, fast model
        try:
             self.model = SentenceTransformer('all-MiniLM-L6-v2')
             self._build_index()
        except Exception as e:
            print(f"Error initializing RAG Explainer: {e}")

    def _build_index(self):
        if not self.kb_data:
            return
            
        texts = [item['text'] for item in self.kb_data]
        embeddings = self.model.encode(texts)
        
        # FAISS index
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(dimension)
        self.index.add(embeddings.astype('float32'))
        print(f"RAG Index built with {len(texts)} entries.")

    def get_explanation(self, query):
        """
        Retrieves the most relevant explanation for a given query (URL features + findings).
        """
        if not self.index or not self.model:
            return "RAG Explainer not initialized."
            
        try:
            # Embed query
            query_embedding = self.model.encode([query])
            
            # Search
            k = 1 # Top 1 match
            D, I = self.index.search(query_embedding.astype('float32'), k)
            
            best_idx = I[0][0]
            distance = D[0][0]
            
            # Distance threshold (lower is better for L2)
            # If distance is too high, maybe generic response?
            # For now return best match.
            
            if 0 <= best_idx < len(self.kb_data):
                return self.kb_data[best_idx]['text']
            else:
                return "No specific explanation found."
                
        except Exception as e:
            print(f"Error retrieving explanation: {e}")
            return "Could not generate explanation."

# Singleton instance or helper if needed
# explainer = RAGExplainer()

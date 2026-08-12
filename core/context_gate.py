import os
import pypdf

class ContextGate:
    def __init__(self):
        pass

    def process_retrieved_data(self, pdf_path: str) -> str:
        """
        Performs Deterministic Structural Stripping (DSS) on retrieved PDF context.
        Extracts raw textual content while stripping executable metadata,
        javascript triggers, embedded objects, and malicious annotations.
        """
        if not os.path.exists(pdf_path):
            return "[SECURITY ERROR: Target context asset not found.]"

        try:
            reader = pypdf.PdfReader(pdf_path)
            extracted_text = []

            for page_num, page in enumerate(reader.pages):
                text = page.extract_text()
                if text:
                    extracted_text.append(text)

            full_context = "\n".join(extracted_text).strip()

            if not full_context:
                return "[SECURITY WARNING: No valid raw text extracted. File structure contained no parseable context.]"

            return full_context

        except Exception as e:
            return f"[SECURITY HARD HARD-BLOCK: PDF parsing failure or malicious structural payload detected: {str(e)}]"

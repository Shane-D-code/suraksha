import io

import fitz
import pytest
from fastapi import UploadFile

from app.api.upload_route import upload_document


@pytest.mark.asyncio
async def test_upload_route_generates_findings_for_blank_pdf():
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), " ")
    pdf_bytes = doc.tobytes()
    doc.close()

    upload_file = UploadFile(
        filename="blank.pdf",
        file=io.BytesIO(pdf_bytes),
    )

    response = await upload_document(upload_file)

    assert response.risk_score >= 20
    assert response.findings

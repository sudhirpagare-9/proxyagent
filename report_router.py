import io
import csv
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from datetime import datetime
from supabase import create_client, Client
import os

router = APIRouter(prefix="/api/reports", tags=["Analytics Reports"])

# Initialize credentials
SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://qwsnkbpsumqobrqkqpht.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "sb_publishable_IPKGvB9I6G7Ix0q2kkpucw_8JdGDaHh"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@router.get("/download-csv")
async def download_historical_csv_report():
    """
    Fetches historical proxy logs from Supabase and streams them live 
    as a downloadable CSV spreadsheet.
    """
    try:
        # Fetch directly from your network_logs table
        response = supabase.table("network_logs").select("*").order("created_at", descending=True).execute()
        records = response.data

        if not records:
            raise HTTPException(status_code=404, detail="No historical logs found to generate a report.")

        # Create an in-memory string buffer to hold CSV data
        stream = io.StringIO()
        headers = records[0].keys()
        
        writer = csv.DictWriter(stream, fieldnames=headers)
        writer.writeheader()
        writer.writerows(records)
        
        # Reset stream position to beginning
        stream.seek(0)
        
        # Format a dynamic timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ai_proxy_matrix_history_{timestamp}.csv"

        return StreamingResponse(
            io.BytesIO(stream.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to generate report payload: {str(err)}")
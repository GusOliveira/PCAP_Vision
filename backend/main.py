
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import parser
import io
import asyncio

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"]
)

@app.get("/")
def read_root():
    return {"message": "NetVisor API is running"}

@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    if not file.filename.endswith('.log'):
        raise HTTPException(status_code=400, detail="Please upload a Zeek .log file.")

    try:
        contents = await file.read()
        log_file = io.StringIO(contents.decode('utf-8'))
        results = parser.parse_zeek_conn_log(log_file)
        return results
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

@app.post("/upload_pcap/")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Please upload a .pcap or .pcapng file.")

    try:
        # Save the uploaded file temporarily to be read by pyshark
        with open(f"/tmp/{file.filename}", "wb") as buffer:
            buffer.write(await file.read())
        
        results = await asyncio.to_thread(parser.parse_pcap_file, f"/tmp/{file.filename}")
        
        if results is None:
            raise HTTPException(status_code=500, detail="Failed to parse pcap file. Check server logs for details.")

        return results
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

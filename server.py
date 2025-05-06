from fastapi import FastAPI, UploadFile, HTTPException, File, Form, Request
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import pandas as pd
import os
import tempfile
import json
import uvicorn
import logging
from datetime import datetime

from src.classify import LogClassifier
from src.security_analyzer import SecurityAnalyzer
from src.data_preprocessing import detect_log_type, preprocess_logs, extract_features, detect_anomalies
from src.utils import save_results_to_file, extract_log_format

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Log Analysis API", description="API for analyzing security logs", version="0.1.0")

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

log_classifier = LogClassifier()
security_analyzer = SecurityAnalyzer()

@app.get("/", response_class=HTMLResponse)
async def show_homepage(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})  # Render homepage

@app.post("/classify/")
async def classify_log_file(file: UploadFile = File(...)):
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")  # Check for file
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as temp:
            temp_path = temp.name
            content = await file.read()
            temp.write(content)
        
        if file.filename.endswith('.csv'):
            output_file = log_classifier.classify_csv(temp_path, 'output.csv')
            return FileResponse(output_file, media_type='text/csv', filename="classified_logs.csv")  # Return classified CSV
        else:
            with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
                logs = f.readlines()
            
            log_type = "generic"
            for line in logs:
                if line.strip():
                    log_type = detect_log_type(line.strip())
                    break
            
            df = preprocess_logs(logs, log_type)
            
            if 'source' not in df.columns:
                df['source'] = os.path.basename(file.filename).split('.')[0]
            
            if 'log_message' not in df.columns:
                df['log_message'] = df['raw'] if 'raw' in df.columns else logs
            
            csv_path = 'temp_logs.csv'
            df.to_csv(csv_path, index=False)
            
            output_file = log_classifier.classify_csv(csv_path, 'output.csv')
            
            os.remove(csv_path)
            
            return FileResponse(output_file, media_type='text/csv', filename="classified_logs.csv")
            
    except Exception as e:
        logger.error(f"Classification error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Classification error: {str(e)}")  # Handling errors
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)  # Cleaning up temp file

@app.post("/analyze/")
async def analyze_log_file(file: UploadFile = File(...)):
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp:
            temp_path = temp.name
            content = await file.read()
            temp.write(content)
        
        if file.filename.endswith('.csv'):
            df = pd.read_csv(temp_path)
            
            if 'log_message' not in df.columns:
                raise HTTPException(status_code=400, detail="CSV must have 'log_message' column")
            
            if 'source' not in df.columns:
                df['source'] = os.path.basename(file.filename).split('.')[0]
        else:
            with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
                logs = f.readlines()
            
            log_type = "generic"
            for line in logs:
                if line.strip():
                    log_type = detect_log_type(line.strip())
                    break
            
            df = preprocess_logs(logs, log_type)
            df = extract_features(df, log_type)
            
            if 'source' not in df.columns:
                df['source'] = os.path.basename(file.filename).split('.')[0]
            
            if 'log_message' not in df.columns:
                df['log_message'] = df['raw'] if 'raw' in df.columns else logs
        
        classified_logs = log_classifier.classify(list(zip(df['source'], df['log_message'])))
        
        analysis_results = security_analyzer.analyze(classified_logs)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"analysis_results_{timestamp}.json"
        save_results_to_file(analysis_results, results_file)
        
        return JSONResponse(content=analysis_results)  #analysis results
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.post("/process_raw_logs/")
async def process_raw_log_text(logs: str = Form(...), log_format: str = Form(None)):
    try:
        log_lines = logs.strip().split('\n')
        
        if not log_format:
            log_type = "generic"
            for line in log_lines:
                if line.strip():
                    log_type = detect_log_type(line.strip())
                    log_format = extract_log_format(line.strip())
                    break
        else:
            if '%h %l %u %t' in log_format:
                log_type = "web_server"
            elif '%date %hostname %program' in log_format:
                log_type = "system"
            else:
                log_type = "generic"
        
        df = preprocess_logs(log_lines, log_type)
        df = extract_features(df, log_type)
        df = detect_anomalies(df, log_type)
        
        if 'source' not in df.columns:
            df['source'] = "raw_input"
        
        if 'log_message' not in df.columns:
            df['log_message'] = df['raw'] if 'raw' in df.columns else log_lines
        
        classified_logs = log_classifier.classify(list(zip(df['source'], df['log_message'])))
        
        analysis_results = security_analyzer.analyze(classified_logs)
        
        analysis_results['log_info'] = {
            'detected_type': log_type,
            'format': log_format,
            'total_logs': len(log_lines),
            'anomalies': int(df['is_anomaly'].sum()) if 'is_anomaly' in df.columns else 0
        }
        
        return JSONResponse(content=analysis_results)
        
    except Exception as e:
        logger.error(f"Raw logs processing error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Raw logs processing error: {str(e)}")  # Handling raw log errors

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)  # Runing the server
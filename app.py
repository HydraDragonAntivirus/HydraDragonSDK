from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import os
import sqlite3
import pefile
import hashlib
import time
import json
import requests
import shutil
import subprocess
import pandas as pd
from antivirus_sdk_cli import FeatureExtractor, SignatureDB, PackedDetectorModel
from typing import List, Dict, Any, Optional

# --- Configuration ---
GITHUB_REPO = "victim/HydraDragonSDK"
DOWNLOADS_FOLDER = 'downloads'
EXTRACTION_FOLDER = 'extracted'
MODEL_PATH = 'packed_detector.joblib'

# Create necessary directories
os.makedirs(DOWNLOADS_FOLDER, exist_ok=True)
os.makedirs(EXTRACTION_FOLDER, exist_ok=True)

# --- FastAPI App Setup ---
app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Mount static files (if any, though none are currently defined in the template)
# app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize SDK components
db = SignatureDB('signatures.db')
fe = FeatureExtractor()

# --- Session Middleware for Flashing Messages (FastAPI requires this) ---
# For flashed messages to work, FastAPI needs a way to handle sessions.
# This is a simple in-memory implementation for demonstration.
# For production, you'd use something like 'starlette.middleware.sessions.SessionMiddleware'
# with a proper SECRET_KEY and backend storage.
app.add_middleware(SessionMiddleware, secret_key="super-secret-key-for-fastapi-sessions")

# --- Helper Functions ---
def is_pe_file(path: str) -> bool:
    try:
        pefile.PE(path, fast_load=True)
        return True
    except pefile.PEFormatError:
        return False

# Function to get flashed messages (FastAPI equivalent)
# This will use a simple list stored in the request session
async def get_flashed_messages(request: Request) -> List[Dict[str, str]]:
    messages = request.session.pop("flashed_messages", [])
    return messages

async def flash_message(request: Request, message: str, category: str = "info"):
    if "flashed_messages" not in request.session:
        request.session["flashed_messages"] = []
    request.session["flashed_messages"].append({"message": message, "category": category})

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Main page, displays files from the database."""
    conn = sqlite3.connect('signatures.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT md5, path, label, added_at FROM samples ORDER BY added_at DESC')
    files = c.fetchall()
    conn.close()
    
    model_exists = os.path.exists(MODEL_PATH)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "files": files,
        "model_exists": model_exists,
        "get_flashed_messages": get_flashed_messages # Pass function to template
    })

@app.get("/sync", response_class=RedirectResponse)
async def sync_github(request: Request):
    """
    Fetches the latest release from GitHub, downloads .7z assets,
    extracts them, and adds new PE files to the database for analysis.
    """
    await flash_message(request, 'Starting sync with GitHub releases...', 'info')
    try:
        api_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        response = requests.get(api_url)
        response.raise_for_status()
        assets = response.json().get('assets', [])
        
        pe_files_found = False
        for asset in assets:
            if asset['name'].endswith('.7z'):
                download_path = os.path.join(DOWNLOADS_FOLDER, asset['name'])
                await flash_message(request, f"Downloading {asset['name']}...", 'info')
                
                with requests.get(asset['browser_download_url'], stream=True) as r:
                    r.raise_for_status()
                    with open(download_path, 'wb') as f:
                        shutil.copyfileobj(r.raw, f)

                await flash_message(request, f"Extracting {asset['name']}...", 'info')
                subprocess.run(['7z', 'e', download_path, f'-o{EXTRACTION_FOLDER}', '-y'], check=True)

                for filename in os.listdir(EXTRACTION_FOLDER):
                    file_path = os.path.join(EXTRACTION_FOLDER, filename)
                    if os.path.isfile(file_path) and is_pe_file(file_path):
                        pe_files_found = True
                        analysis, features = fe.extract(file_path)
                        added = db.add_sample(file_path, -1, features, analysis)
                        await flash_message(request, 
                                            f"Added new file: {filename}" if added else f"File already exists: {filename}", 
                                            'success' if added else 'secondary')
        
        if not pe_files_found:
            await flash_message(request, 'Sync complete. No new PE files found in release assets.', 'info')

    except Exception as e:
        await flash_message(request, f"An error occurred: {e}", 'error')
    finally:
        if os.path.exists(EXTRACTION_FOLDER):
            shutil.rmtree(EXTRACTION_FOLDER)
        os.makedirs(EXTRACTION_FOLDER)

    return RedirectResponse(url="/", status_code=302)

@app.get("/flag/{md5}/{label}", response_class=RedirectResponse)
async def flag_file(request: Request, md5: str, label: int):
    """Updates the label for a given file MD5."""
    if label not in [0, 1]:
        await flash_message(request, 'Invalid label.', 'error')
    else:
        conn = sqlite3.connect('signatures.db')
        c = conn.cursor()
        c.execute('UPDATE samples SET label=? WHERE md5=?', (label, md5))
        conn.commit()
        conn.close()
        await flash_message(request, 'File label updated successfully.', 'success')
    return RedirectResponse(url="/", status_code=302)

@app.get("/scan/{md5}", response_class=RedirectResponse)
async def scan_file(request: Request, md5: str):
    """Scans a file with the pre-trained ML model."""
    if not os.path.exists(MODEL_PATH):
        await flash_message(request, f"Model file not found at '{MODEL_PATH}'. Please train the model first.", "error")
        return RedirectResponse(url="/", status_code=302)

    try:
        conn = sqlite3.connect('signatures.db')
        c = conn.cursor()
        c.execute("SELECT features_json FROM samples WHERE md5 = ?", (md5,))
        result = c.fetchone()
        conn.close()

        if not result:
            await flash_message(request, "File not found in database.", "error")
            return RedirectResponse(url="/", status_code=302)

        features = json.loads(result[0])
        df = pd.DataFrame([features]).fillna(0)
        
        model = PackedDetectorModel.load(MODEL_PATH)
        
        # Align columns between model and new data
        model_features = model.model.feature_names_in_
        df = df.reindex(columns=model_features, fill_value=0)

        prediction = model.predict(df)
        label = prediction['preds'][0]
        
        # Update the label in DB
        conn = sqlite3.connect('signatures.db')
        c = conn.cursor()
        c.execute('UPDATE samples SET label=? WHERE md5=?', (label, md5))
        conn.commit()
        conn.close()
        
        result_text = "Malicious" if label == 1 else "Benign"
        await flash_message(request, f"ML Scan complete. Result for {md5[:10]}...: {result_text}", 'info')

    except Exception as e:
        await flash_message(request, f"An error occurred during scanning: {e}", "error")

    return RedirectResponse(url="/", status_code=302)

@app.get("/train", response_class=RedirectResponse)
async def train_model_endpoint(request: Request):
    """Trains the ML model from the labeled data in the database."""
    try:
        df = db.to_dataframe()
        labeled_df = df[df['label'].isin([0, 1])]
        
        if len(labeled_df) < 2: # Changed from 10 to 2 for easier testing/initial training
            await flash_message(request, "Not enough labeled samples to train. Need at least 2.", "warning")
            return RedirectResponse(url="/", status_code=302)

        y = labeled_df['label']
        X = labeled_df.drop(columns=[c for c in ['label', 'md5', 'path'] if c in labeled_df.columns])

        model = PackedDetectorModel()
        await flash_message(request, "Starting model training... this might take a while.", "info")
        
        report = model.train(X, y, model_out=MODEL_PATH)
        
        await flash_message(request, f"Model training complete! Saved to {MODEL_PATH}. ROC AUC: {report.get('roc_auc', 'N/A')}", "success")

    except Exception as e:
        await flash_message(request, f"An error occurred during training: {e}", "error")

    return RedirectResponse(url="/", status_code=302)

# --- Main Entry Point (for local development with uvicorn) ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
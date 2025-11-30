---
title: HydraDragon Analysis Dashboard
emoji: 🐉
colorFrom: green
colorTo: blue
sdk: docker
app_port: 7860
---

# HydraDragon SDK & Analysis Dashboard

This repository contains the HydraDragon Machine Learning SDK and a web-based dashboard for analyzing PE files.

## Features

*   **GitHub Release Sync:** Downloads and processes `.7z` archives from the latest GitHub Release.
*   **PE File Analysis:** Extracts features from PE files using the `antivirus_sdk_cli`.
*   **Manual Classification:** A web UI to label files as 'Benign' or 'Malicious'.
*   **ML-Powered Scanning:** Train a RandomForest model on your labeled data and use it to automatically classify new files.

## Cloud Deployment (Hugging Face Spaces)

This application is configured for deployment on **Hugging Face Spaces**, a free platform for hosting ML applications.

### Deployment Steps:

1.  **Clone the Space:**
    ```bash
    git clone https://huggingface.co/spaces/HydraDragonAntivirus/HydraDragon-Dashboard
    ```
    *   When prompted for a password, use an access token with write permissions. Generate one from your settings: [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)

2.  **Install `hf CLI` (if not already installed):**
    ```powershell
    powershell -ExecutionPolicy ByPass -c "irm https://hf.co/cli/install.ps1 | iex"
    ```

3.  **Download the Space (Optional, if you cloned directly):**
    ```bash
    hf download HydraDragonAntivirus/HydraDragon-Dashboard --repo-type=space
    ```

4.  **Add your application files:**
    Ensure your `requirements.txt`, `app.py`, and `Dockerfile` are in the root of your cloned repository. These files have already been prepared for you.

    *   **`requirements.txt`:**
        ```
        pefile
        capstone
        numpy
        pandas
        scikit-learn
        joblib
        tqdm
        requests
        fastapi
        uvicorn[standard]
        ```

    *   **`app.py`:** Your FastAPI application logic.

    *   **`Dockerfile`:**
        ```dockerfile
        # Read the doc: https://huggingface.co/docs/hub/spaces-sdks-docker
        FROM python:3.9
        RUN useradd -m -u 1000 user
        USER user
        ENV PATH="/home/user/.local/bin:$PATH"
        WORKDIR /app
        COPY --chown=user ./requirements.txt requirements.txt
        RUN pip install --no-cache-dir --upgrade -r requirements.txt
        COPY --chown=user . /app
        CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
        ```

5.  **Commit and Push:**
    ```bash
    git add .
    git commit -m "Update application for Hugging Face Spaces deployment"
    git push
    ```

    Your Space should be running on its Hugging Face page after a few moments! It will listen on port `7860`.

## How to Use the Dashboard

1.  **Access the Dashboard:** Once deployed on Hugging Face Spaces, your dashboard will be available at the public URL provided by Hugging Face (e.g., `https://huggingface.co/spaces/YourUsername/YourSpaceName`).
2.  **Sync Files:** Click the **Sync from GitHub** button to fetch the latest release assets. New PE files will be added to the database as "Unlabeled".
3.  **Label Files:** Manually label some files as "Benign" or "Malicious". You need a good number of both to train an effective model.
4.  **Train Model:** Once you have enough labeled data, click the **Train Model** button. This will create a `packed_detector.joblib` file within the Space's storage.
5.  **Scan Files:** For any remaining "Unlabeled" files, click the **Scan with ML** button to automatically classify them using your newly trained model.

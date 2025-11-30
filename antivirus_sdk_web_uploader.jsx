// Antivirus SDK Uploader - React single-file app
// Usage: build as a static site and host on GitHub Pages or any static host.
// This component provides a file upload UI, lets the user flag uploaded files
// as benign or malicious, and commits the file (and a small metadata JSON)
// to a GitHub repository using the GitHub REST API (client-side). 
//
// SECURITY WARNING: This approach requires the user to provide a GitHub Personal
// Access Token (PAT) with `repo` scope for private repos or `public_repo` for public.
// Do NOT hardcode tokens in client code. For production, use a backend to handle
// authentication securely.
//
// Files are committed under: /uploads/{timestamp}_{filename}
// Metadata is committed as: /uploads/{timestamp}_{filename}.metadata.json
// Commit message includes the user flag: "flag:malicious" or "flag:benign".
//
// Deployment: Create a repo, enable GitHub Pages in Settings (branch: gh-pages),
// or add a GitHub Actions workflow to deploy from main.

import React, { useState } from 'react';

export default function AntivirusUploader() {
  const [file, setFile] = useState(null);
  const [flag, setFlag] = useState('benign');
  const [token, setToken] = useState('');
  const [repo, setRepo] = useState('username/repo');
  const [branch, setBranch] = useState('main');
  const [status, setStatus] = useState('');
  const [progress, setProgress] = useState(0);

  function onFileChange(e) {
    setFile(e.target.files[0]);
  }

  function b64EncodeFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const dataUrl = reader.result; // data:<mime>;base64,DATA
        const base64 = dataUrl.split(',')[1];
        resolve(base64);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  async function uploadToGitHub({ token, repo, branch, path, contentBase64, message }) {
    const url = `https://api.github.com/repos/${repo}/contents/${encodeURIComponent(path)}`;
    const body = {
      message: message,
      content: contentBase64,
      branch: branch
    };
    const res = await fetch(url, {
      method: 'PUT',
      headers: {
        Authorization: `token ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`GitHub API error: ${res.status} ${text}`);
    }
    return res.json();
  }

  async function handleUpload(e) {
    e.preventDefault();
    if (!file) return setStatus('Choose a file');
    if (!token) return setStatus('Provide GitHub token');
    if (!repo) return setStatus('Provide repo in form owner/repo');
    setStatus('Reading file...');
    try {
      const base64 = await b64EncodeFile(file);
      const ts = Date.now();
      const uploadPath = `uploads/${ts}_${file.name}`;
      const metaPath = `uploads/${ts}_${file.name}.metadata.json`;
      setStatus('Uploading file...');
      setProgress(20);
      const message = `upload: ${file.name} flag:${flag}`;
      await uploadToGitHub({ token, repo, branch, path: uploadPath, contentBase64: base64, message });
      setProgress(70);
      const metadata = {
        filename: file.name,
        uploaded_at: new Date(ts).toISOString(),
        flag: flag,
        uploader: 'web',
        repo: repo
      };
      await uploadToGitHub({ token, repo, branch, path: metaPath, contentBase64: btoa(JSON.stringify(metadata, null, 2)), message: `metadata: ${file.name} flag:${flag}` });
      setProgress(100);
      setStatus('Upload complete');
    } catch (err) {
      console.error(err);
      setStatus('Upload failed: ' + err.message);
    }
  }

  return (
    <div className="min-h-screen p-6 bg-slate-50">
      <div className="max-w-2xl mx-auto bg-white p-6 rounded-2xl shadow">
        <h1 className="text-2xl font-semibold mb-4">Antivirus SDK — Upload & Flag</h1>
        <form onSubmit={handleUpload} className="space-y-4">
          <div>
            <label className="block text-sm font-medium">GitHub Repo (owner/repo)</label>
            <input className="w-full p-2 border rounded" value={repo} onChange={e => setRepo(e.target.value)} />
          </div>
          <div>
            <label className="block text-sm font-medium">Branch</label>
            <input className="w-full p-2 border rounded" value={branch} onChange={e => setBranch(e.target.value)} />
          </div>
          <div>
            <label className="block text-sm font-medium">Personal Access Token (store securely)</label>
            <input className="w-full p-2 border rounded" value={token} onChange={e => setToken(e.target.value)} type="password" />
          </div>
          <div>
            <label className="block text-sm font-medium">File</label>
            <input type="file" onChange={onFileChange} />
          </div>
          <div>
            <label className="block text-sm font-medium">Flag</label>
            <select value={flag} onChange={e => setFlag(e.target.value)} className="p-2 border rounded">
              <option value="benign">Benign</option>
              <option value="malicious">Malicious</option>
            </select>
          </div>

          <div className="flex gap-2">
            <button className="px-4 py-2 bg-blue-600 text-white rounded" type="submit">Upload & Flag</button>
            <button type="button" className="px-4 py-2 bg-gray-200 rounded" onClick={() => { setFile(null); setStatus(''); setProgress(0); }}>Reset</button>
          </div>

          <div>
            <div className="text-sm">Status: {status}</div>
            <div className="w-full bg-gray-200 h-2 rounded mt-2">
              <div style={{ width: `${progress}%` }} className="h-2 bg-green-500 rounded" />
            </div>
          </div>

        </form>

        <div className="mt-6 text-xs text-gray-500">
          <p>Notes:</p>
          <ul className="list-disc ml-5">
            <li>GitHub token must have repo permissions to create files.</li>
            <li>For production, route uploads through a backend to avoid exposing tokens.</li>
            <li>Files are stored in the repo under <code>uploads/</code>.</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

/*
README & Deployment
-------------------
1) Create a repository on GitHub (e.g. owner: your-username, repo: antivirus-uploader)
2) Create a static site branch or enable GitHub Pages on the repo (Settings -> Pages -> source: gh-pages or main/docs)
3) Build this React app (example using Vite or Create React App) and publish to gh-pages branch, or use GitHub Actions:

Example GitHub Actions workflow (.github/workflows/pages.yml):

name: Deploy Pages
on:
  push:
    branches:
      - main

jobs:
  build-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install
        run: npm ci
      - name: Build
        run: npm run build
      - name: Deploy
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./dist

Security: do NOT store PATs in client-side code. Use OAuth or a backend that stores tokens in secrets.
*/
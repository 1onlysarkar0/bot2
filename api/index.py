from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import os
import asyncio
from main import bot_runtime, api_status, api_health, api_post_emote

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def root():
    # Reuse the logic from main.py's api_home if possible or simple placeholder
    return """
    <html>
    <head><title>Bot Server</title></head>
    <body><h1>🎮 Bot Server is Running on Vercel</h1></body>
    </html>
    """

@app.get("/status")
async def status():
    return JSONResponse(content=bot_runtime)

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/post")
async def post_emote(request: Request):
    data = await request.json()
    # Logic to handle post emote via FastAPI
    return {"status": "received"}

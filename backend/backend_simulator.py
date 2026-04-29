from fastapi import FastAPI

app = FastAPI(title="Dummy Backend")

@app.get("/")
async def home():
    return {"message": "Backend is running"}

@app.get("/hello")
async def hello():
    return {"message": "Hello from backend"}

@app.post("/comment")
async def comment():
    return {"message": "Comment received"}

@app.get("/files")
async def files():
    return {"message": "Files endpoint reached"}

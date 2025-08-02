import requests
from fastapi import FastAPI
from fastapi.responses import RedirectResponse,JSONResponse
import redis
import hashlib
from urllib.parse import urljoin, urlparse
from enum import Enum
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

class ResponseMessage(Enum):
    INVALID_URL = "Invalid URL or URL does not exist"
    SAME_DOMAIN = "Cannot shorten URL from my domain"
    UNKNOWN_ERROR = "An error occurred in validating the url"
    DOES_NOT_EXIST = "Shortened URL not found"
    OK = "Ok"


r = redis.Redis(host=os.getenv("REDIS_HOSTNAME"), port=os.getenv("REDIS_PORT"), decode_responses=True)

base_url = f"http://{os.getenv("APP_HOSTNAME")}"
BASE_LENGTH = 7
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins="*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def hash_url(url: str, hash_len=BASE_LENGTH) -> str:
    hash_obj = hashlib.sha256()
    hash_obj.update(url.encode("utf-8"))
    digest = hash_obj.hexdigest()
    shortened_digest = digest[:hash_len]

    existing_url = r.get(shortened_digest)

    # no collision and key exists
    if existing_url and existing_url == url:
        return shortened_digest

    # collision for a different url, increase length by 1 for hash
    if existing_url and existing_url != url:
        shortened_digest = hash_url(url, hash_len + 1)

    r.set(shortened_digest, url)

    return shortened_digest

def shorten_url(url: str):
    digest = hash_url(url)
    return urljoin(base_url, digest)

def check_url_validity(url):
    try: 
        if (urlparse(url).netloc == os.getenv("APP_HOSTNAME")):
            return ResponseMessage.SAME_DOMAIN
        if requests.head(url).status_code == 404:
            print("URL points to no kown locatin")
            return ResponseMessage.INVALID_URL
    except:
        return ResponseMessage.INVALID_URL
    return ResponseMessage.OK


@app.post("/")
async def read_url(url: str):
    source = r.get(url)
    if source:
        return source
    is_valid = check_url_validity(url)

    if is_valid == ResponseMessage.OK:
        res_url =  shorten_url(url)
        return JSONResponse(content={"input": url, "output": res_url})
    
    return JSONResponse(content={"message": is_valid.value}, status_code=400)

@app.get("/{digest}")
async def redirect_to_source(digest: str):
    print("Redirecting")
    source = r.get(digest)
    if (source):
        return RedirectResponse(source, status_code=302)
    return JSONResponse({"message": ResponseMessage.DOES_NOT_EXIST}, status_code=404)

if __name__ == "__main__":
    while True:
        url = input("Enter the URL to be shortened, q to exit:")
        if url == "q":
            print("Out...")
            break
        print("The shortened URL is: " + shorten_url(url))

import requests
from fastapi import FastAPI
from fastapi.responses import Response, RedirectResponse
import redis
import hashlib
from urllib.parse import urljoin, urlparse
from enum import Enum

APP_HOSTNAME = "localhost:8000"
REDIS_HOSTNAME = "localhost"
REDIS_PORT = 6379

class ErrorMessage(Enum):
    INVALID_URL = "Invalid URL or URL does not exist"
    SAME_DOMAIN = "Cannot shorten URL from my domain"
    UNKNOWN_ERROR = "An error occurred in validating the url"

r = redis.Redis(host=REDIS_HOSTNAME, port=REDIS_PORT, decode_responses=True)

base_url = f"http://{APP_HOSTNAME}"
BASE_LENGTH = 7
app = FastAPI()

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
        if (urlparse(url).netloc == APP_HOSTNAME):
            return ErrorMessage.SAME_DOMAIN
        
        if requests.head(url).status_code == 404:
            return ErrorMessage.INVALID_URL
    except:
        return ErrorMessage.INVALID_URL
    return True


@app.post("/shorten")
async def read_url(url: str):
    is_valid = check_url_validity(url)
    if type(is_valid) == bool and is_valid:
        return shorten_url(url)
    
    return Response(content=is_valid.value, status_code=400)

@app.get("/{digest}")
async def redirect_to_source(digest: str):
    source = r.get(digest)
    if (source):
        return RedirectResponse(source, status_code=302)
    return Response(status_code=404)

if __name__ == "__main__":
    while True:
        url = input("Enter the URL to be shortened, q to exit:")
        if url == "q":
            print("Out...")
            break
        print("The shortened URL is: " + shorten_url(url))

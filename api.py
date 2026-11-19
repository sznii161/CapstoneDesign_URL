from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from inference import load_detector, predict_url


app = FastAPI(title="캡스톤 URL 검사")
load_detector()


class UrlRequest(BaseModel):
    url: str


@app.post("/predict/url")
def check_url(request: UrlRequest):
    try:
        return predict_url(request.url)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

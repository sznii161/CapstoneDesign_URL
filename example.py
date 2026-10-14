"""Run from any working directory: python /path/to/example.py 'URL'."""
import argparse
import json
from inference import load_detector, predict_url

def main():
    parser=argparse.ArgumentParser(description='URL 탐지 모델 v1: 네트워크 접속 없는 로컬 추론')
    parser.add_argument('url',help='원본 URL 문자열')
    args=parser.parse_args()
    try:
        load_detector()  # Startup: load once, reuse through predict_url().
        print(json.dumps(predict_url(args.url),ensure_ascii=False))
    except (ValueError,TypeError) as exc:
        parser.exit(2,json.dumps({'error':str(exc)},ensure_ascii=False)+'\n')

if __name__=='__main__':main()

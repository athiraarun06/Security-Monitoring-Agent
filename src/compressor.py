import os
import requests
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

class SecurityLogCompressor:
    def __init__(self):
        self.api_key = os.getenv('SCALEDOWN_API_KEY')
        self.api_url = 'https://api.scaledown.xyz/compress/raw/'
        self.target_model = 'gpt-4o-mini'
        if not self.api_key:
            raise ValueError('API key not found')
    
    def compress_logs(self, logs, prompt='Analyze security threats'):
        headers = {'x-api-key': self.api_key, 'Content-Type': 'application/json'}
        payload = {'context': logs, 'prompt': prompt, 'model': self.target_model, 'max_tokens': 500, 'scaledown': {'rate': 'auto'}}
        
        import time
        start = time.time()
        response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
        latency = int((time.time() - start) * 1000)
        
        if response.status_code == 200:
            result = response.json()
            orig = result.get('usage', {}).get('prompt_tokens_uncompressed', len(logs.split()))
            comp = result.get('usage', {}).get('prompt_tokens', len(logs.split()) // 2)
            return {'content': result.get('choices', [{}])[0].get('message', {}).get('content', ''), 'compressed_context': result.get('compressed_context', logs), 'original_tokens': orig, 'compressed_tokens': comp, 'successful': True, 'latency_ms': latency}
        else:
            raise Exception(f'API error {response.status_code}')
    
    def get_compression_stats(self, result):
        orig = result.get('original_tokens', 0)
        comp = result.get('compressed_tokens', 0)
        saved = orig - comp
        percent = (saved / orig * 100) if orig > 0 else 0
        ratio = (orig / comp) if comp > 0 else 0
        cost = (saved / 1000000) * 0.15
        return {'original_tokens': orig, 'compressed_tokens': comp, 'tokens_saved': saved, 'savings_percent': round(percent, 2), 'compression_ratio': round(ratio, 2), 'latency_ms': result.get('latency_ms', 0), 'target_model': self.target_model, 'estimated_cost_saved': round(cost, 6)}

from flask import Flask, request, render_template_string
import joblib
import pandas as pd
from urllib.parse import urlparse

app = Flask(__name__)

model = joblib.load('phishing_model.pkl')

def extract_features(url):
    keywords = [
        'login', 'verify', 'update',
        'secure', 'bank', 'free', 'giftcard'
    ]

    return pd.DataFrame([{
        'url_length': len(url),
        'qty_dots': url.count('.'),
        'qty_hyphens': url.count('-'),
        'is_https': int(urlparse(url).scheme == 'https'),
        'qty_keywords': sum(
            1 for word in keywords if word in url.lower()
        )
    }])

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    confidence = None
    css_class = ''
    url = ''

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        parsed = urlparse(url)

        if parsed.scheme not in ['http', 'https'] or not parsed.hostname:
            result = 'INVALID URL'
            css_class = 'invalid'
        else:
            features = extract_features(url)
            prediction = int(model.predict(features)[0])

            result = 'PHISHING DETECTED' if prediction == 1 else 'PREDICTED SAFE'
            confidence = round(
                max(model.predict_proba(features)[0]) * 100, 2
            )
            css_class = 'phishing' if prediction == 1 else 'safe'

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
    <title>SecureURL</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    * { box-sizing: border-box; }
    body {
        background: #081426; color: white;
        font-family: Arial; margin: 0;
    }
    header { padding: 25px 8%; color: #38bdf8; font-size: 25px; font-weight: bold; }
    main { max-width: 750px; margin: 65px auto; padding: 25px; text-align: center; }
    h1 { font-size: 38px; }
    p { color: #a8bad3; }
    .scanner { background: #14243c; padding: 30px; border-radius: 15px; margin-top: 35px; }
    input { width: 100%; padding: 17px; border: 1px solid #345071; border-radius: 8px; background: #0b1930; color: white; font-size: 16px; }
    button { width: 100%; margin-top: 18px; padding: 16px; background: #087bd3; color: white; border: 0; border-radius: 8px; font-size: 17px; cursor: pointer; }
    .result { margin-top: 25px; padding: 20px; border-radius: 10px; }
    .phishing { background: #49252d; }
    .safe { background: #183b36; }
    .invalid { background: #443c24; }
    footer { text-align: center; color: #8295b0; padding: 30px; }
    </style>
    </head>
    <body>
    <header>🛡 SecureURL</header>
    <main>
    <h1>Phishing URL Detection</h1>
    <p>Analyze suspicious URLs using a Random Forest ML model.</p>
    <div class="scanner">
    <form method="POST">
    <input name="url" placeholder="https://example.com" value="{{ url }}" required>
    <button type="submit">🔍 Analyze URL</button>
    </form>
    {% if result %}
    <div class="result {{ css_class }}">
    <h2>{{ result }}</h2>
    {% if confidence is not none %}
    <p>Model confidence: {{ confidence }}%</p>
    {% endif %}
    <p>Model prediction only. Not a guarantee of website safety.</p>
    </div>
    {% endif %}
    </div>
    </main>
    <footer>SecureURL | Random Forest Machine Learning Project</footer>
    </body>
    </html>
    """, result=result, confidence=confidence,
         css_class=css_class, url=url)

@app.route('/healthz')
def health():
    return 'OK', 200
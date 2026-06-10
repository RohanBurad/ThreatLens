from flask import Flask, render_template, request, jsonify, send_file
from utils.analyzer import analyze_url
from utils.report import generate_report
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/report', methods=['POST'])
def report():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    result = analyze_url(url)
    pdf_path = generate_report(url, result)
    return jsonify({'report_path': pdf_path})

@app.route('/download-report', methods=['POST'])
def download_report():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    result = analyze_url(url)
    pdf_path = generate_report(url, result)
    abs_path = os.path.abspath(pdf_path)
    return send_file(abs_path, as_attachment=True, download_name='ThreatLens_Report.pdf', mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)
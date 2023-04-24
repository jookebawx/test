from flask import Flask, render_template, request
import PyPDF2

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('Submitpage.html')

@app.route('/upload', methods=['POST'])
def upload():
    # Check if the file key is present in the request
    if 'file' not in request.files:
        return 'No file uploaded.', 400

    # Get the uploaded file from the request object
    uploaded_file = request.files['file']

    # Check if the file is empty
    if uploaded_file.filename == '':
        return 'No file selected.', 400

    # Open the uploaded file using PyPDF2
    pdf_reader = PyPDF2.PdfReader(uploaded_file)

    # Extract the text from the PDF file
    text = ''
    for i in range(len(pdf_reader.pages)):
        page = pdf_reader.pages[i]
        text += page.extract_text()

    # Render the extracted text on a new page
    return render_template('result.html', text=text)

if __name__ == '__main__':
    app.run(debug=True)

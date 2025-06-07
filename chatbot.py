import google.generativeai as genai
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Configure the API key
API_KEY = "Replace with your actual API key" 
genai.configure(api_key=API_KEY)

# Initialize the Gemini model
model = genai.GenerativeModel('gemini-1.5-pro')  # Using the correct model name

# Start a chat session
chat = model.start_chat(history=[])

def get_response(user_input):
    """
    Sends user input to the Gemini API and returns the response.
    """
    try:
        response = chat.send_message(user_input)
        return response.text
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat_endpoint():
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'response': 'Please provide a message.'})
    
    response = get_response(user_message)
    return jsonify({'response': response})

if __name__ == '__main__':
    app.run(debug=True)
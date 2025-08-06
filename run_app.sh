#!/bin/bash
# Run the Email Validator Streamlit App

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Run the Streamlit app
echo "Starting Email Validator Streamlit App..."
echo "The app will open in your browser at http://localhost:8501"
streamlit run email_validator_app.py

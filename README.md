# Email Validator Streamlit App

A user-friendly web interface for validating email addresses from CSV or Excel files.

## Features

- 📁 **File Upload**: Support for CSV, XLSX, and XLS files
- 🔍 **Auto-detection**: Automatically detects email columns in your data
- ⚡ **Format Validation**: Fast regex-based email format validation
- 📧 **SMTP Validation**: Optional deep validation by checking with mail servers
- 📊 **Interactive Results**: View validation results with charts and metrics
- 📥 **Download Results**: Export valid emails, bounced emails, and summary reports
- 🎯 **Progress Tracking**: Real-time progress updates during validation

## Quick Start

### Option 1: Using the Run Script (Recommended)
```bash
./run_app.sh
```

### Option 2: Manual Setup
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # On macOS/Linux
# or
.venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run email_validator_app.py
```

## Usage

1. **Start the App**: Run the script and open http://localhost:8501 in your browser
2. **Upload File**: Drag and drop or browse for your CSV/Excel file
3. **Select Column**: Choose the column containing email addresses (auto-detected)
4. **Configure Settings**: 
   - Enable SMTP validation for more accurate results (slower)
   - Adjust timeout settings if needed
5. **Validate**: Click "Validate Emails" to start processing
6. **Review Results**: View metrics, charts, and detailed results
7. **Download**: Export valid emails, bounced emails, or summary reports

## Validation Methods

### Format Validation (Default)
- Fast regex-based validation
- Checks if email follows proper format (e.g., user@domain.com)
- Good for basic cleanup and format checking

### SMTP Validation (Optional)
- Contacts actual mail servers to verify email existence
- More accurate but significantly slower
- May be blocked by some mail servers
- Recommended for smaller lists or when accuracy is critical

## File Requirements

- **Supported formats**: CSV, XLSX, XLS
- **Email column**: Must contain email addresses (can be auto-detected)
- **File size**: No hard limit, but larger files will take longer to process

## Output Files

The app generates three downloadable files:

1. **valid_emails.csv**: List of valid email addresses
2. **bounced_emails.csv**: List of invalid/bounced email addresses with reasons
3. **validation_summary.csv**: Overall statistics and metrics

## Dependencies

- `streamlit`: Web app framework
- `pandas`: Data manipulation and analysis
- `dnspython`: DNS resolution for MX records
- `openpyxl`: Excel file support (.xlsx)
- `xlrd`: Excel file support (.xls)

## Original Command-Line Script

The original command-line version (`validateMails.py`) is still available and can be used as:

```bash
python validateMails.py your_file.csv --smtp --output results
```

## Troubleshooting

### SMTP Validation Issues
- Some mail servers may block validation attempts
- Try reducing the timeout or disabling SMTP validation
- Results may vary depending on your network and the target mail servers

### File Upload Issues
- Ensure your file is in CSV, XLSX, or XLS format
- Check that the email column contains valid data
- For large files, consider processing in smaller batches

### Dependencies
- If you encounter import errors, ensure all requirements are installed:
  ```bash
  pip install -r requirements.txt
  ```

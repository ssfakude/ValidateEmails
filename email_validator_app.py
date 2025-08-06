#!/usr/bin/env python3
"""
Email Validator Streamlit App
A web interface for validating emails from CSV or Excel files.
"""

import streamlit as st
import pandas as pd
import re
import smtplib
import socket
import dns.resolver
from email.mime.text import MIMEText
from typing import List, Tuple, Dict
from pathlib import Path
import io
import time

class EmailValidator:
    def __init__(self, smtp_check=False, timeout=10):
        """
        Initialize EmailValidator
        
        Args:
            smtp_check (bool): Whether to perform SMTP validation
            timeout (int): Timeout for SMTP connections in seconds
        """
        self.smtp_check = smtp_check
        self.timeout = timeout
        self.email_regex = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
    
    def validate_email_format(self, email: str) -> bool:
        """
        Validate email format using regex
        
        Args:
            email (str): Email address to validate
            
        Returns:
            bool: True if format is valid, False otherwise
        """
        if not email or not isinstance(email, str):
            return False
        
        email = email.strip().lower()
        return bool(self.email_regex.match(email))
    
    def get_mx_record(self, domain: str) -> str:
        """
        Get MX record for domain
        
        Args:
            domain (str): Domain to check
            
        Returns:
            str: MX record or None if not found
        """
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            # Get the MX record with lowest preference (highest priority)
            mx_record = min(mx_records, key=lambda x: x.preference)
            return str(mx_record.exchange).rstrip('.')
        except Exception:
            return None
    
    def smtp_validate(self, email: str) -> bool:
        """
        Validate email using SMTP
        
        Args:
            email (str): Email address to validate
            
        Returns:
            bool: True if email exists, False otherwise
        """
        if not self.validate_email_format(email):
            return False
        
        domain = email.split('@')[1]
        mx_record = self.get_mx_record(domain)
        
        if not mx_record:
            return False
        
        try:
            # Connect to SMTP server
            server = smtplib.SMTP(timeout=self.timeout)
            server.connect(mx_record, 25)
            server.helo('validator.com')
            server.mail('test@validator.com')
            
            # Check if email exists
            code, message = server.rcpt(email)
            server.quit()
            
            # 250 means email exists, 550 means it doesn't
            return code == 250
            
        except Exception as e:
            st.warning(f"SMTP validation failed for {email}: {str(e)}")
            return False
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Validate email with specified method
        
        Args:
            email (str): Email address to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, reason)
        """
        if not email or pd.isna(email):
            return False, "Empty email"
        
        email = str(email).strip()
        
        # First check format
        if not self.validate_email_format(email):
            return False, "Invalid format"
        
        # If SMTP check is enabled, perform it
        if self.smtp_check:
            if self.smtp_validate(email):
                return True, "Valid (SMTP verified)"
            else:
                return False, "SMTP validation failed"
        else:
            return True, "Valid format"
    
    def process_dataframe(self, df: pd.DataFrame, email_column: str, progress_callback=None) -> Dict:
        """
        Process DataFrame and validate emails
        
        Args:
            df (pd.DataFrame): DataFrame containing emails
            email_column (str): Name of the email column
            progress_callback: Callback function for progress updates
            
        Returns:
            Dict: Results containing valid and bounced emails
        """
        if email_column not in df.columns:
            raise ValueError(f"Column '{email_column}' not found in file")
        
        valid_emails = []
        bounced_emails = []
        total_emails = len(df)
        
        for index, email in df[email_column].items():
            is_valid, reason = self.validate_email(email)
            
            email_info = {
                'email': str(email).strip() if email else '',
                'row': index + 1,
                'reason': reason
            }
            
            if is_valid:
                valid_emails.append(email_info)
            else:
                bounced_emails.append(email_info)
            
            # Update progress
            if progress_callback and (index + 1) % 10 == 0:
                progress = (index + 1) / total_emails
                progress_callback(progress, f"Processed {index + 1}/{total_emails} emails")
        
        return {
            'total': len(df),
            'valid': valid_emails,
            'bounced': bounced_emails,
            'valid_count': len(valid_emails),
            'bounced_count': len(bounced_emails)
        }


def detect_email_column(df: pd.DataFrame) -> str:
    """
    Auto-detect email column in DataFrame
    
    Args:
        df (pd.DataFrame): DataFrame to analyze
        
    Returns:
        str: Name of the email column or None if not found
    """
    # Look for columns with 'email' in the name
    email_columns = [col for col in df.columns if 'email' in col.lower()]
    if email_columns:
        return email_columns[0]
    
    # Look for columns that might contain emails
    for col in df.columns:
        sample_values = df[col].dropna().head(5)
        if not sample_values.empty:
            for value in sample_values:
                if isinstance(value, str) and '@' in value and '.' in value:
                    return col
    
    return None


def create_download_link(df: pd.DataFrame, filename: str, label: str):
    """
    Create a download link for DataFrame
    
    Args:
        df (pd.DataFrame): DataFrame to download
        filename (str): Name of the file
        label (str): Label for the download button
    """
    csv = df.to_csv(index=False)
    st.download_button(
        label=label,
        data=csv,
        file_name=filename,
        mime='text/csv'
    )


def main():
    st.set_page_config(
        page_title="Email Validator",
        page_icon="📧",
        layout="wide"
    )
    
    st.title("📧 Email Validator")
    st.markdown("Upload a CSV or Excel file to validate email addresses")
    
    # Sidebar for settings
    st.sidebar.header("⚙️ Settings")
    
    smtp_check = st.sidebar.checkbox(
        "Enable SMTP Validation",
        help="Slower but more accurate validation by checking with mail servers"
    )
    
    timeout = st.sidebar.slider(
        "SMTP Timeout (seconds)",
        min_value=5,
        max_value=30,
        value=10,
        help="Timeout for SMTP connections"
    )
    
    # File upload
    st.header("📁 Upload File")
    uploaded_file = st.file_uploader(
        "Choose a CSV or Excel file",
        type=['csv', 'xlsx', 'xls'],
        help="Upload a file containing email addresses"
    )
    
    if uploaded_file is not None:
        try:
            # Read the uploaded file
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            
            st.success(f"✅ File uploaded successfully! Found {len(df)} rows.")
            
            # Show file preview
            st.subheader("📋 File Preview")
            st.dataframe(df.head(), use_container_width=True)
            
            # Column selection
            st.subheader("📬 Select Email Column")
            
            # Auto-detect email column
            detected_column = detect_email_column(df)
            
            if detected_column:
                st.info(f"🔍 Auto-detected email column: **{detected_column}**")
                default_index = list(df.columns).index(detected_column)
            else:
                st.warning("⚠️ Could not auto-detect email column. Please select manually.")
                default_index = 0
            
            email_column = st.selectbox(
                "Choose the column containing email addresses:",
                options=df.columns.tolist(),
                index=default_index
            )
            
            # Show sample emails from selected column
            sample_emails = df[email_column].dropna().head(5).tolist()
            if sample_emails:
                st.write("**Sample emails from selected column:**")
                for email in sample_emails:
                    st.write(f"• {email}")
            
            # Validation button
            if st.button("🚀 Validate Emails", type="primary"):
                # Create validator
                validator = EmailValidator(smtp_check=smtp_check, timeout=timeout)
                
                # Show validation info
                if smtp_check:
                    st.warning("⏳ SMTP validation enabled - this may take longer...")
                
                # Progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                def update_progress(progress, message):
                    progress_bar.progress(progress)
                    status_text.text(message)
                
                # Start validation
                start_time = time.time()
                
                try:
                    results = validator.process_dataframe(
                        df, 
                        email_column, 
                        progress_callback=update_progress
                    )
                    
                    # Complete progress
                    progress_bar.progress(1.0)
                    status_text.text("✅ Validation completed!")
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    # Display results
                    st.header("📊 Validation Results")
                    
                    # Summary metrics
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Emails", results['total'])
                    
                    with col2:
                        st.metric("Valid Emails", results['valid_count'])
                    
                    with col3:
                        st.metric("Bounced Emails", results['bounced_count'])
                    
                    with col4:
                        valid_rate = (results['valid_count'] / results['total'] * 100) if results['total'] > 0 else 0
                        st.metric("Valid Rate", f"{valid_rate:.1f}%")
                    
                    st.info(f"⏱️ Validation completed in {duration:.2f} seconds")
                    
                    # Show detailed results
                    tab1, tab2, tab3 = st.tabs(["✅ Valid Emails", "❌ Bounced Emails", "📈 Summary"])
                    
                    with tab1:
                        if results['valid']:
                            valid_df = pd.DataFrame(results['valid'])
                            st.dataframe(valid_df, use_container_width=True)
                            create_download_link(
                                valid_df,
                                "valid_emails.csv",
                                "📥 Download Valid Emails"
                            )
                        else:
                            st.info("No valid emails found.")
                    
                    with tab2:
                        if results['bounced']:
                            bounced_df = pd.DataFrame(results['bounced'])
                            st.dataframe(bounced_df, use_container_width=True)
                            create_download_link(
                                bounced_df,
                                "bounced_emails.csv",
                                "📥 Download Bounced Emails"
                            )
                        else:
                            st.info("No bounced emails found.")
                    
                    with tab3:
                        summary_data = {
                            'Metric': ['Total Emails', 'Valid Emails', 'Bounced Emails', 'Valid Rate (%)'],
                            'Value': [
                                results['total'],
                                results['valid_count'],
                                results['bounced_count'],
                                round(valid_rate, 2)
                            ]
                        }
                        summary_df = pd.DataFrame(summary_data)
                        st.dataframe(summary_df, use_container_width=True)
                        create_download_link(
                            summary_df,
                            "validation_summary.csv",
                            "📥 Download Summary"
                        )
                        
                        # Visualization
                        st.subheader("📊 Validation Chart")
                        chart_data = pd.DataFrame({
                            'Status': ['Valid', 'Bounced'],
                            'Count': [results['valid_count'], results['bounced_count']]
                        })
                        st.bar_chart(chart_data.set_index('Status'))
                
                except Exception as e:
                    st.error(f"❌ Error during validation: {str(e)}")
                    
        except Exception as e:
            st.error(f"❌ Error reading file: {str(e)}")
    
    else:
        # Show instructions when no file is uploaded
        st.info("👆 Please upload a CSV or Excel file to get started")
        
        st.subheader("📝 Instructions")
        st.markdown("""
        1. **Upload your file**: Choose a CSV or Excel file containing email addresses
        2. **Select email column**: The app will try to auto-detect the email column
        3. **Configure settings**: Optionally enable SMTP validation for more accurate results
        4. **Validate**: Click the validate button to process your emails
        5. **Download results**: Get separate files for valid emails, bounced emails, and summary
        
        **Supported file formats**: CSV, XLSX, XLS
        
        **Validation methods**:
        - **Format validation**: Checks if email follows proper format (fast)
        - **SMTP validation**: Contacts mail servers to verify email exists (slower but more accurate)
        """)


if __name__ == "__main__":
    main()

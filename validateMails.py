#!/usr/bin/env python3
"""
Email Validator Script
Validates emails from CSV or Excel files and returns lists of valid and bounced emails.
"""

import pandas as pd
import re
import smtplib
import socket
import dns.resolver
from email.mime.text import MIMEText
from typing import List, Tuple, Dict
import argparse
import sys
from pathlib import Path

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
            print(f"SMTP validation failed for {email}: {str(e)}")
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
    
    def process_file(self, file_path: str, email_column: str = None) -> Dict:
        """
        Process CSV or Excel file and validate emails
        
        Args:
            file_path (str): Path to the file
            email_column (str): Name of the email column (auto-detect if None)
            
        Returns:
            Dict: Results containing valid and bounced emails
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file based on extension
        if file_path.suffix.lower() == '.csv':
            df = pd.read_csv(file_path)
        elif file_path.suffix.lower() in ['.xlsx', '.xls']:
            df = pd.read_excel(file_path)
        else:
            raise ValueError("Unsupported file format. Use CSV or Excel files.")
        
        # Auto-detect email column if not specified
        if email_column is None:
            email_columns = [col for col in df.columns if 'email' in col.lower()]
            if not email_columns:
                # Look for columns that might contain emails
                for col in df.columns:
                    sample_value = str(df[col].dropna().iloc[0]) if not df[col].dropna().empty else ""
                    if '@' in sample_value and '.' in sample_value:
                        email_column = col
                        break
                
                if email_column is None:
                    raise ValueError("No email column found. Please specify the column name.")
            else:
                email_column = email_columns[0]
        
        if email_column not in df.columns:
            raise ValueError(f"Column '{email_column}' not found in file")
        
        print(f"Processing {len(df)} emails from column '{email_column}'...")
        
        valid_emails = []
        bounced_emails = []
        
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
            
            # Progress indicator
            if (index + 1) % 100 == 0:
                print(f"Processed {index + 1}/{len(df)} emails...")
        
        return {
            'total': len(df),
            'valid': valid_emails,
            'bounced': bounced_emails,
            'valid_count': len(valid_emails),
            'bounced_count': len(bounced_emails)
        }
    
    def save_results(self, results: Dict, output_file: str = None):
        """
        Save results to CSV files
        
        Args:
            results (Dict): Results from process_file
            output_file (str): Base name for output files
        """
        if output_file is None:
            output_file = "email_validation"
        
        # Remove extension if provided
        output_file = Path(output_file).stem
        
        # Save valid emails
        if results['valid']:
            valid_df = pd.DataFrame(results['valid'])
            valid_file = f"{output_file}_valid.csv"
            valid_df.to_csv(valid_file, index=False)
            print(f"Valid emails saved to: {valid_file}")
        
        # Save bounced emails
        if results['bounced']:
            bounced_df = pd.DataFrame(results['bounced'])
            bounced_file = f"{output_file}_bounced.csv"
            bounced_df.to_csv(bounced_file, index=False)
            print(f"Bounced emails saved to: {bounced_file}")
        
        # Save summary
        summary = {
            'metric': ['Total Emails', 'Valid Emails', 'Bounced Emails', 'Valid Rate (%)'],
            'value': [
                results['total'],
                results['valid_count'],
                results['bounced_count'],
                round((results['valid_count'] / results['total']) * 100, 2) if results['total'] > 0 else 0
            ]
        }
        summary_df = pd.DataFrame(summary)
        summary_file = f"{output_file}_summary.csv"
        summary_df.to_csv(summary_file, index=False)
        print(f"Summary saved to: {summary_file}")


def main():
    parser = argparse.ArgumentParser(description='Validate emails from CSV or Excel files')
    parser.add_argument('file', help='Path to CSV or Excel file')
    parser.add_argument('--column', '-c', help='Email column name (auto-detect if not specified)')
    parser.add_argument('--smtp', '-s', action='store_true', help='Enable SMTP validation (slower but more accurate)')
    parser.add_argument('--output', '-o', help='Output file base name (default: email_validation)')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='SMTP timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    try:
        # Create validator
        validator = EmailValidator(smtp_check=args.smtp, timeout=args.timeout)
        
        # Process file
        print(f"Validating emails from: {args.file}")
        if args.smtp:
            print("SMTP validation enabled - this may take longer...")
        
        results = validator.process_file(args.file, args.column)
        
        # Print results
        print("\n" + "="*50)
        print("VALIDATION RESULTS")
        print("="*50)
        print(f"Total emails processed: {results['total']}")
        print(f"Valid emails: {results['valid_count']}")
        print(f"Bounced emails: {results['bounced_count']}")
        print(f"Valid rate: {round((results['valid_count'] / results['total']) * 100, 2)}%")
        
        # Save results
        validator.save_results(results, args.output)
        
        print("\nValidation completed successfully!")
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
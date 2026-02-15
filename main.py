from flask import Flask, render_template, request, redirect, url_for, flash, session
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore import FieldFilter
import os
import PyPDF2
import docx
import re
from collections import Counter
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from email.utils import parseaddr, formataddr
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default-dev-key-12345')

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Firebase Initialization
# Check if already initialized to avoid errors during reloads
if not firebase_admin._apps:
    # Check for environment variable (for Render/Production)
    firebase_creds = os.environ.get('FIREBASE_CREDENTIALS')
    
    if firebase_creds:
        print("🔐 Using FIREBASE_CREDENTIALS environment variable")
        import json
        try:
            cred_dict = json.loads(firebase_creds)
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
        except Exception as e:
            print(f"❌ Error loading FIREBASE_CREDENTIALS: {e}")
            # Fallback to default or file if env var fails
            if os.path.exists('serviceAccountKey.json'):
                cred = credentials.Certificate('serviceAccountKey.json')
                firebase_admin.initialize_app(cred)
            else:
                firebase_admin.initialize_app()
    elif os.path.exists('serviceAccountKey.json'):
        print("🔒 Using service account key for Firebase")
        cred = credentials.Certificate('serviceAccountKey.json')
        firebase_admin.initialize_app(cred)
    else:
        print("☁️ Using Default Credentials (Cloud) for Firebase")
        firebase_admin.initialize_app()

# Global DB client - initialized lazily if needed, but we'll try to init once here
db = None
try:
    db = firestore.client()
    print("✅ Firestore client initialized successfully", flush=True)
except Exception as e:
    print(f"⚠️ Initial Firestore connection failed: {e}. Will retry on request.", flush=True)

@app.route('/health')
def health():
    return {"status": "healthy", "firestore": db is not None}, 200

    
# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path):
    text = ""
    try:
        if file_path.endswith('.pdf'):
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page in pdf_reader.pages:
                    text += page.extract_text()
        elif file_path.endswith('.docx'):
            doc = docx.Document(file_path)
            for paragraph in doc.paragraphs:
                text += paragraph.text + '\n'
        elif file_path.endswith('.txt'):
            with open(file_path, 'r', encoding='utf-8') as file:
                text = file.read()
    except Exception as e:
        print(f"Error extracting text: {e}")
    return text

def extract_candidate_info(text):
    # Extract email
    email = extract_email_from_text(text) or ""

    
    # Extract phone
    phone_pattern = r'(\+\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}'
    phones = re.findall(phone_pattern, text)
    phone = ''.join(phones[0]) if phones else ""
    
    # Extract name (first line usually contains name)
    lines = text.strip().split('\n')
    name = lines[0].strip() if lines else ""
    
    # Extract skills
    skills_keywords = [
        'python', 'java', 'javascript', 'react', 'angular', 'vue', 'node',
        'sql', 'mysql', 'postgresql', 'mongodb', 'redis', 'docker', 'kubernetes',
        'aws', 'azure', 'gcp', 'git', 'jenkins', 'ci/cd', 'devops', 'agile',
        'html', 'css', 'bootstrap', 'jquery', 'php', 'laravel', 'django',
        'flask', 'spring', 'hibernate', 'rest', 'api', 'microservices'
    ]
    
    found_skills = []
    text_lower = text.lower()
    for skill in skills_keywords:
        if skill in text_lower:
            found_skills.append(skill.title())
    
    # Extract experience years
    exp_pattern = r'(\d+)[\s]*(?:years?|yrs?)[\s]*(?:of)?[\s]*(?:experience|exp)'
    exp_matches = re.findall(exp_pattern, text.lower())
    experience_years = int(exp_matches[0]) if exp_matches else 0
    
    # Extract education
    education_keywords = ['bachelor', 'master', 'phd', 'degree', 'university', 'college', 'mba', 'btech', 'mtech']
    education_info = []
    for keyword in education_keywords:
        if keyword in text.lower():
            education_info.append(keyword.title())
    
    return {
        'name': name,
        'email': email,
        'phone': phone,
        'skills': ', '.join(found_skills),
        'experience_years': experience_years,
        'education': ', '.join(education_info)
    }

def calculate_score(candidate_info, text):
    try:
        docs = db.collection('scoring_rules').stream()
        rules = []
        for doc in docs:
            rules.append(doc.to_dict())
        
        total_score = 0
        text_lower = text.lower()
        skills_lower = candidate_info['skills'].lower()
        education_lower = candidate_info['education'].lower()
        
        for rule in rules:
            rule_type = rule.get('rule_type')
            keyword = rule.get('keyword', '')
            points = rule.get('points', 0)

            if rule_type == 'skill' and keyword.lower() in skills_lower:
                total_score += points
            elif rule_type == 'experience' and candidate_info['experience_years'] >= int(keyword) if keyword.isdigit() else 0:
                total_score += points
            elif rule_type == 'education' and keyword.lower() in education_lower:
                total_score += points
            elif rule_type == 'general' and keyword.lower() in text_lower:
                total_score += points
        
        return total_score
    except Exception as e:
        print(f"Error calculating score: {e}")
        return 0

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            doc_ref = db.collection('users').document(username)
            doc = doc_ref.get()
            
            if doc.exists:
                user_data = doc.to_dict()
                if user_data.get('is_active', False) and check_password_hash(user_data.get('password_hash'), password):
                    session['user_id'] = doc.id
                    session['username'] = user_data.get('username')
                    session['role'] = user_data.get('role')
                    flash(f'Welcome back, {user_data.get("username")}!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password.', 'error')
            else:
                flash('Invalid username or password.', 'error')
        except Exception as e:
            flash(f'Error logging in: {e}', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
            
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('register.html')
        
        try:
            # Check if username exists
            doc_ref = db.collection('users').document(username)
            if doc_ref.get().exists:
                flash('Username already exists.', 'error')
                return render_template('register.html')
            
            # Check if email exists
            # Check if email exists
            email_query = db.collection('users').where(filter=FieldFilter('email', '==', email)).limit(1).stream()
            if any(email_query):
                flash('Email already exists.', 'error')
                return render_template('register.html')
            
            # Create new user
            password_hash = generate_password_hash(password)
            doc_ref.set({
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'role': 'hr_manager',
                'is_active': True,
                'created_at': firestore.SERVER_TIMESTAMP
            })
            
        except Exception as e:
            flash(f'Error registering user: {e}', 'error')
            return render_template('register.html')
        
        flash('Registration successful! Please log in with your new account.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_id = session['user_id']
        
        # Get statistics
        # Note: Counting documents in Firestore can be expensive if there are many documents.
        # For a small app, this is fine. For scale, use aggregation queries or distributed counters.
        candidates_ref = db.collection('candidates').where(filter=FieldFilter('uploaded_by', '==', user_id))
        total_candidates = len(list(candidates_ref.stream()))
        
        rules_ref = db.collection('scoring_rules')
        total_rules = len(list(rules_ref.stream()))
        
        jobs_ref = db.collection('job_postings').where(filter=FieldFilter('created_by', '==', user_id)).where(filter=FieldFilter('is_active', '==', True))
        active_jobs = len(list(jobs_ref.stream()))
        
        # Get recent candidates
        recent_ref = db.collection('candidates').where(filter=FieldFilter('uploaded_by', '==', user_id)).order_by('uploaded_at', direction=firestore.Query.DESCENDING).limit(5)
        recent_candidates = [doc.to_dict() for doc in recent_ref.stream()]
        
        return render_template('dashboard.html', 
                             total_candidates=total_candidates,
                             total_rules=total_rules,
                             active_jobs=active_jobs,
                             recent_candidates=recent_candidates)
    except Exception as e:
        print(f"Dashboard error: {e}")
        flash(f"Error loading dashboard: {e}", "error")
        return render_template('dashboard.html', 
                             total_candidates=0,
                             total_rules=0,
                             active_jobs=0,
                             recent_candidates=[])

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_resume():
    if request.method == 'POST':
        print("=== UPLOAD DEBUG ===")
        print(f"User ID: {session['user_id']}")
        print(f"Files in request: {list(request.files.keys())}")
        
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        print(f"File selected: {file.filename}")
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            print(f"File saved to: {file_path}")
            
            # Extract text and candidate info
            text = extract_text_from_file(file_path)
            print(f"Extracted text length: {len(text)}")
            
            candidate_info = extract_candidate_info(text)
            print(f"Candidate info: {candidate_info}")

            if not candidate_info['email']:
                flash("Could not extract candidate email. Please ensure the resume is clear and valid.", "error")
                return redirect(request.url)

            
            score = calculate_score(candidate_info, text)
            print(f"Calculated score: {score}")
            
            # Get form data
            form_name = request.form.get('name', '').strip()
            form_email = request.form.get('email', '').strip()
            form_phone = request.form.get('phone', '').strip()
            
            # Use form data if provided, otherwise use extracted data
            final_name = form_name if form_name else candidate_info['name']
            final_email = form_email if form_email else candidate_info['email']
            final_phone = form_phone if form_phone else candidate_info['phone']
            
            print(f"Final data - Name: {final_name}, Email: {final_email}, Phone: {final_phone}")
            
            # Save to Firestore
            try:
                doc_ref = db.collection('candidates').document()
                doc_ref.set({
                    'name': final_name,
                    'email': final_email, 
                    'phone': final_phone, 
                    'filename': filename, 
                    'file_path': file_path, 
                    'extracted_text': text, 
                    'skills': candidate_info['skills'], 
                    'experience_years': candidate_info['experience_years'], 
                    'education': candidate_info['education'], 
                    'total_score': score, 
                    'uploaded_by': session['user_id'], 
                    'status': 'uploaded', 
                    'uploaded_at': firestore.SERVER_TIMESTAMP,
                    'last_contact_date': None,
                    'interview_status': 'pending'
                })
                candidate_id = doc_ref.id
                print(f"Candidate saved with ID: {candidate_id}")
            except Exception as e:
                print(f"Error saving to Firestore: {e}")
                flash(f"Error saving candidate: {e}", "error")
                return redirect(url_for('upload_resume'))
            
            print(f"Candidate saved with ID: {candidate_id}")
            print("=== END UPLOAD DEBUG ===")
            
            flash(f'Resume uploaded successfully! Candidate: {final_name}, Score: {score}', 'success')
            return redirect(url_for('candidates'))
        else:
            flash('Invalid file type. Please upload PDF, DOCX, or TXT files.', 'error')
    
    return render_template('upload.html')

@app.route('/candidates')
@login_required
def candidates():
    try:
        candidates_ref = db.collection('candidates').where(filter=FieldFilter('uploaded_by', '==', session['user_id'])).order_by('total_score', direction=firestore.Query.DESCENDING)
        candidates_data = []
        for doc in candidates_ref.stream():
            c = doc.to_dict()
            c['id'] = doc.id
            candidates_data.append(c)
        
        # Debug: Print to console to see if data exists
        print(f"Found {len(candidates_data)} candidates for user {session['user_id']}")
        
        return render_template('candidates.html', candidates=candidates_data)
    except Exception as e:
        print(f"Error fetching candidates: {e}")
        return render_template('candidates.html', candidates=[])

@app.route('/debug-candidates')
@login_required
def debug_candidates():
    try:
        docs = db.collection('candidates').stream()
        all_candidates = []
        for doc in docs:
            c = doc.to_dict()
            c['id'] = doc.id
            all_candidates.append(c)
        
        response = f"<h2>All Candidates in Database:</h2>"
        response += f"<p>Total: {len(all_candidates)}</p>"
        for candidate in all_candidates:
            response += f"<p>{candidate}</p>"
        
        return response
    except Exception as e:
        return f"Error: {e}"

@app.route('/scoring-rules', methods=['GET', 'POST'])
@login_required
def scoring_rules():
    if request.method == 'POST':
        try:
            rule_type = request.form['rule_type']
            keyword = request.form['keyword']
            points = int(request.form['points'])
            
            db.collection('scoring_rules').add({
                'rule_type': rule_type,
                'keyword': keyword,
                'points': points,
                'created_by': session['user_id'],
                'created_at': firestore.SERVER_TIMESTAMP
            })
            
            flash('Scoring rule added successfully!', 'success')
            return redirect(url_for('scoring_rules'))
        except Exception as e:
            flash(f'Error adding rule: {e}', 'error')
    
    # Get existing rules
    try:
        rules_ref = db.collection('scoring_rules').order_by('created_at', direction=firestore.Query.DESCENDING)
        rules = []
        for doc in rules_ref.stream():
            r = doc.to_dict()
            r['id'] = doc.id
            rules.append(r)
    except Exception as e:
        print(f"Error fetching rules: {e}")
        rules = []
    
    return render_template('scoring_rules.html', rules=rules)

@app.route('/job-posting', methods=['GET', 'POST'])
@login_required
def job_posting():
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form['title']
            description = request.form.get('description', '')
            requirements = request.form.get('requirements', '')
            candidate_limit = int(request.form['candidate_limit'])
            
            # Email configuration
            sender_email = request.form['sender_email']
            sender_password = request.form['sender_password']
            sender_name = request.form.get('sender_name', 'HR Manager')
            company_name = request.form.get('company_name', 'Your Company')
            email_subject = request.form.get('email_subject', 'Interview Invitation - {job_title}')
            email_template = request.form['email_template']
            
            # Save job posting to Firestore
            job_ref = db.collection('job_postings').add({
                'title': title,
                'description': description,
                'requirements': requirements,
                'max_candidates': candidate_limit,
                'created_by': session['user_id'],
                'created_at': firestore.SERVER_TIMESTAMP,
                'is_active': True
            })
            
            # Get top candidates (Client-side filtering for complex email validation)
            candidates_ref = db.collection('candidates').where(filter=FieldFilter('uploaded_by', '==', session['user_id'])).order_by('total_score', direction=firestore.Query.DESCENDING)
            
            all_candidates = candidates_ref.stream()
            top_candidates = []
            
            count = 0
            for doc in all_candidates:
                if count >= candidate_limit:
                    break
                    
                c = doc.to_dict()
                email = c.get('email', '')
                
                # Check for valid email logic
                if email and '@' in email and '.' in email:
                    c['id'] = doc.id
                    top_candidates.append(c)
                    count += 1
            
            if not top_candidates:
                flash('⚠️ Job posting created, but no candidates with valid email addresses found.', 'warning')
                return redirect(url_for('job_posting'))
            
            print(f"🎯 Found {len(top_candidates)} candidates with email addresses")
            
            # Send personalized emails to top candidates
            emails_sent = 0
            emails_failed = 0
            successful_emails = []
            
            for candidate in top_candidates:
                candidate_name = candidate.get('name') or 'Candidate'
                candidate_email = candidate.get('email')
                candidate_phone = candidate.get('phone') or 'Not provided'
                # Attributes might not exist in old documents, handle safely
                total_score = round(candidate.get('total_score', 0), 1)
                
                try:
                    # Create personalized email content
                    personalized_subject = email_subject.format(
                        job_title=title,
                        company_name=company_name,
                        sender_name=sender_name,
                        candidate_name=candidate_name
                    )
                    
                    personalized_content = email_template.format(
                        job_title=title,
                        company_name=company_name,
                        sender_name=sender_name,
                        candidate_name=candidate_name,
                        total_score=total_score,
                        # Fallbacks for missing scores
                        technical_score=0, 
                        experience_score=0,
                        education_score=0,
                        candidate_phone=candidate_phone
                    )
                    
                    # Send email
                    success = send_email_simple(
                        sender_email, 
                        sender_password, 
                        candidate_email, 
                        personalized_subject, 
                        personalized_content, 
                        sender_name
                    )
                    
                    if success:
                        emails_sent += 1
                        successful_emails.append({
                            'name': candidate_name,
                            'email': candidate_email,
                            'score': total_score
                        })
                        print(f"✅ Email sent to {candidate_name} ({candidate_email}) - Score: {total_score}")
                    else:
                        emails_failed += 1
                        print(f"❌ Failed to send email to {candidate_name} ({candidate_email})")
                        
                except Exception as e:
                    print(f"❌ Error processing candidate {candidate_name}: {str(e)}")
                    emails_failed += 1
            
            # Show detailed results
            if emails_sent > 0:
                success_msg = f'🎉 Job posting created successfully! 📧 Sent {emails_sent} interview invitations automatically!'
                flash(success_msg, 'success')
                
                if emails_failed > 0:
                    flash(f'⚠️ {emails_failed} emails failed to send. Check your email settings.', 'warning')
            else:
                flash('❌ Job posting created, but failed to send any interview invitations. Please check your email settings.', 'error')
                
        except Exception as e:
            flash(f'❌ Error creating job posting: {str(e)}', 'error')
            print(f"Job posting error: {str(e)}")
        
        return redirect(url_for('job_posting'))
    
    # GET request - show the form
    # Get existing job postings
    try:
        jobs_ref = db.collection('job_postings').where(filter=FieldFilter('created_by', '==', session['user_id'])).order_by('created_at', direction=firestore.Query.DESCENDING)
        jobs = []
        for doc in jobs_ref.stream():
            j = doc.to_dict()
            j['id'] = doc.id
            # Convert timestamp to string if needed for template
            # j['created_at'] = j['created_at'].strftime('%Y-%m-%d') if j.get('created_at') else ''
            jobs.append(j)
            
    except Exception as e:
        print(f"Error fetching jobs: {e}")
        jobs = []
    
    return render_template('job_posting.html', jobs=jobs)

# Add this email sending function
def send_email(sender_email, sender_password, recipient_email, subject, content, sender_name):
    """Send email using SMTP"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"{sender_name} <{sender_email}>"
        msg['To'] = recipient_email
        msg['Subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(content, 'plain'))
        
        # Gmail SMTP configuration
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Enable security
        server.login(sender_email, sender_password)
        
        # Send email
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        
        print(f"Email sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        print(f"Failed to send email to {recipient_email}: {str(e)}")
        return False
    
@app.route('/users')
@login_required
def users():
    # Only admins can access user management
    if session.get('role') != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('users.html')

# Add this route after your existing routes
@app.route('/delete_rule/<rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    try:
        # Check if rule exists
        doc_ref = db.collection('scoring_rules').document(rule_id)
        if doc_ref.get().exists:
            doc_ref.delete()
            flash('Rule deleted successfully!', 'success')
        else:
            flash('Rule not found!', 'error')
            
    except Exception as e:
        flash(f'Error deleting rule: {str(e)}', 'error')
    
    return redirect(url_for('scoring_rules'))

def extract_email_from_text(text):
    """Enhanced email extraction with multiple patterns and validation"""
    
    # Multiple email patterns to catch different formats
    email_patterns = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Standard email
        r'\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Z|a-z]{2,}\b',  # With spaces
        r'[Ee]mail\s*:?\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})',  # After "Email:"
        r'[Mm]ail\s*:?\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})',   # After "Mail:"
        r'[Cc]ontact\s*:?\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', # After "Contact:"
    ]
    
    found_emails = []
    
    # Try each pattern
    for pattern in email_patterns:
        matches = re.findall(pattern, text)
        if matches:
            for match in matches:
                # If match is a tuple (from grouped patterns), take the first group
                email = match[0] if isinstance(match, tuple) else match
                email = email.strip().lower()
                
                # Validate email format
                if validate_email_format(email):
                    found_emails.append(email)
    
    # Remove duplicates and return the first valid email
    unique_emails = list(set(found_emails))
    
    # Prefer professional emails (avoid temporary/spam emails)
    professional_emails = [email for email in unique_emails 
                          if not any(spam in email for spam in ['temp', 'throwaway', '10minute'])]
    
    return professional_emails[0] if professional_emails else (unique_emails[0] if unique_emails else None)

def validate_email_format(email):
    """Validate email format and check for common issues"""
    if not email or len(email) < 5:
        return False
    
    # Basic format check
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False
    
    # Check for invalid characters
    invalid_chars = [' ', '\n', '\t', '\r']
    if any(char in email for char in invalid_chars):
        return False
    
    return True

def extract_phone_from_text(text):
    """Enhanced phone number extraction"""
    
    phone_patterns = [
        r'\+?1?[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',  # US format
        r'\+?([0-9]{1,3})[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{3,4})[-.\s]?([0-9]{3,4})',  # International
        r'[Pp]hone\s*:?\s*([\+0-9\-\.\s\(\)]{10,15})',  # After "Phone:"
        r'[Mm]obile\s*:?\s*([\+0-9\-\.\s\(\)]{10,15})',  # After "Mobile:"
        r'[Cc]ell\s*:?\s*([\+0-9\-\.\s\(\)]{10,15})',   # After "Cell:"
    ]
    
    for pattern in phone_patterns:
        matches = re.search(pattern, text)
        if matches:
            if len(matches.groups()) == 1:
                return matches.group(1).strip()
            else:
                # Reconstruct phone number from groups
                phone_parts = [group for group in matches.groups() if group]
                return ''.join(phone_parts)
    
    return None

def send_email_simple(sender_email, sender_password, recipient_email, subject, content, sender_name):
    """Send email with enhanced error handling and logging"""
    try:
        # Validate inputs
        if not all([sender_email, sender_password, recipient_email, subject, content]):
            print("❌ Missing required email parameters")
            return False
        
        if not validate_email_format(recipient_email):
            print(f"❌ Invalid recipient email format: {recipient_email}")
            return False
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = formataddr((sender_name, sender_email))
        msg['To'] = recipient_email
        msg['Subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(content, 'plain', 'utf-8'))
        
        # Determine SMTP settings based on email provider
        if 'gmail.com' in sender_email.lower():
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
        elif 'outlook.com' in sender_email.lower() or 'hotmail.com' in sender_email.lower():
            smtp_server = 'smtp-mail.outlook.com'
            smtp_port = 587
        elif 'yahoo.com' in sender_email.lower():
            smtp_server = 'smtp.mail.yahoo.com'
            smtp_port = 587
        else:
            smtp_server = 'smtp.gmail.com'  # Default to Gmail
            smtp_port = 587
        
        print(f"📧 Attempting to send email via {smtp_server}:{smtp_port}")
        
        # Create secure connection and send email
        context = ssl.create_default_context()
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context)
            server.login(sender_email, sender_password)
            server.send_message(msg)
            
        print(f"✅ Email sent successfully to {recipient_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ SMTP Authentication failed for {sender_email}: {str(e)}")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"❌ Recipient refused {recipient_email}: {str(e)}")
        return False
    except smtplib.SMTPServerDisconnected as e:
        print(f"❌ SMTP server disconnected: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Email sending failed: {str(e)}")
        return False
    
def process_resume(file_path):
    """Process uploaded resume and extract candidate information"""
    try:
        # Extract text based on file type
        if file_path.lower().endswith('.pdf'):
            text = extract_text_from_pdf(file_path)
        elif file_path.lower().endswith(('.docx', '.doc')):
            text = extract_text_from_docx(file_path)
        else:
            raise ValueError("Unsupported file format")
        
        print(f"📄 Extracted text length: {len(text)} characters")
        
        # Extract candidate information
        candidate_data = {
            'name': extract_name(text),
            'email': extract_email_from_text(text),  # ← NEW
            'phone': extract_phone_from_text(text),  # ← NEW
            'skills': extract_skills(text),
            'experience': extract_experience(text),
            'education': extract_education(text),
            'raw_text': text[:1000]  # ← NEW: Store sample for debugging
        }
        
        # Debug output
        print(f"📧 Extracted email: {candidate_data['email']}")
        print(f"📱 Extracted phone: {candidate_data['phone']}")
        print(f"👤 Extracted name: {candidate_data['name']}")
        
        # Calculate scores
        scores = calculate_scores(candidate_data)
        candidate_data.update(scores)
        
        return candidate_data
        
    except Exception as e:
        print(f"❌ Error processing resume: {str(e)}")
        raise Exception(f"Resume processing failed: {str(e)}")
    
@app.route('/check-candidate-emails')
@login_required
def check_candidate_emails():
    """Debug route to check which candidates have valid emails"""
    try:
        candidates_ref = db.collection('candidates').where(filter=FieldFilter('uploaded_by', '==', session['user_id'])).order_by('total_score', direction=firestore.Query.DESCENDING)
        candidates_list = []
        for doc in candidates_ref.stream():
            c = doc.to_dict()
            candidates_list.append((
                doc.id, 
                c.get('name'), 
                c.get('email'), 
                c.get('phone'), 
                c.get('total_score'), 
                c.get('filename')
            ))
        candidates = candidates_list
    except Exception as e:
        print(f"Error checking emails: {e}")
        candidates = []
    
    response = f"""
    <html>
    <head>
        <title>Candidate Email Check</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .valid-email {{ background-color: #d4edda; }}
            .invalid-email {{ background-color: #f8d7da; }}
            .no-email {{ background-color: #fff3cd; }}
        </style>
    </head>
    <body>
        <h1>📧 Candidate Email Validation Report</h1>
        <p><strong>Total Candidates:</strong> {len(candidates)}</p>
        
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Phone</th>
                    <th>Score</th>
                    <th>Filename</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
    """
    
    valid_emails = 0
    for candidate in candidates:
        name = candidate[1] or 'Unknown'
        email = candidate[2] or ''
        phone = candidate[3] or ''
        score = candidate[4] or 0
        filename = candidate[5] or ''
        
        # Determine email status
        if not email:
            status = "No Email"
            css_class = "no-email"
        elif validate_email_format(email):
            status = "✅ Valid"
            css_class = "valid-email"
            valid_emails += 1
        else:
            status = "❌ Invalid"
            css_class = "invalid-email"
        
        response += f"""
                <tr class="{css_class}">
                    <td>{name}</td>
                    <td>{email}</td>
                    <td>{phone}</td>
                    <td>{score:.1f}</td>
                    <td>{filename}</td>
                    <td>{status}</td>
                </tr>
        """
    
    response += f"""
            </tbody>
        </table>
        
        <div style="margin-top: 20px; padding: 15px; background: #e7f3ff; border-radius: 5px;">
            <h3>📊 Summary</h3>
            <p><strong>Candidates with valid emails:</strong> {valid_emails}/{len(candidates)}</p>
            <p><strong>Ready for interview invitations:</strong> {valid_emails} candidates</p>
        </div>
        
        <div style="margin-top: 20px;">
            <a href="/job-posting" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                📝 Create Job Posting
            </a>
            <a href="/candidates" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-left: 10px;">
                👥 View All Candidates
            </a>
        </div>
    </body>
    </html>
    """
    
    return response

# SQL initialization removed

if __name__ == '__main__':
    #def deprecated_init_db(): # SQL initialization logic - DO NOT USE
    app.run(debug=True, host='0.0.0.0', port=5000)
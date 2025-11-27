import re, os, requests
from io import BytesIO
from functools import wraps
import json, qrcode, time
from flask_cors import CORS 

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, send_file, jsonify, make_response, abort, current_app
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import pandas as pd

import config

app = Flask(__name__)
app.config.from_object('config')
app.secret_key = app.config['SECRET_KEY']
UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
CORS(app)

# DB connection helper
def get_db_connection():
    return psycopg2.connect(
        host=config.DB_HOST,
        dbname=config.DB_NAME,
        user=config.DB_USER,
        password=config.DB_PASSWORD
    )

# Initialize the DB (call once or at startup)
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    # batches, departments tables for filtering
    cur.execute('''
        CREATE TABLE IF NOT EXISTS batches (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS departments (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            degree TEXT NOT NULL
        );
    ''')
    # users table for admin/teachers/students auth
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            batch_id INTEGER,
            department_id INTEGER,
            batch_status TEXT,
            admission_date TEXT,
            FOREIGN KEY (batch_id) REFERENCES batches(id),
            FOREIGN KEY (department_id) REFERENCES departments(id)
        );

    ''')
    # students table as requested
    cur.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'student',
            father_name TEXT,
            caste TEXT,
            cnic TEXT UNIQUE,
            roll_no TEXT UNIQUE,
            batch TEXT,
            department TEXT,
            year TEXT,
            enrollment TEXT,
            emergency_contact TEXT,
            relation TEXT,
            blood_group TEXT,
            address TEXT,
            image_path TEXT,
            qr_code TEXT
        );

    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS agent_sessions (
          id SERIAL PRIMARY KEY,
          admin_user_id TEXT,
          started_at TIMESTAMPTZ DEFAULT now(),
          ended_at TIMESTAMPTZ,
          initial_query TEXT
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS agent_actions (
          id SERIAL PRIMARY KEY,
          session_id INT REFERENCES agent_sessions(id),
          action_name TEXT,
          action_payload JSONB,
          result JSONB,
          created_at TIMESTAMPTZ DEFAULT now()
        );
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
          id SERIAL PRIMARY KEY,
          admin_user_id TEXT,
          change_type TEXT,
          target TEXT,
          details JSONB,
          created_at TIMESTAMPTZ DEFAULT now()
        );
    ''')

    conn.commit()
    cur.close()
    conn.close()


# helper: check admin existence
def admin_exists():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE role = %s LIMIT 1", ('admin',))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists

@app.context_processor
def inject_admin_exists():
    return dict(admin_exists=admin_exists())

# simple decorator for role-based access
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get('logged_in'):
                flash('Please login first.', 'warning')
                return redirect(url_for('login'))
            if session.get('role') not in [r.lower() for r in roles]:
                flash('Access denied for your role.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# utility: allowed file
def allowed_image(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in config.ALLOWED_IMAGE_EXT

# ROUTES
@app.route('/')
def home():
    if session.get('logged_in'):
        role = session.get('role')
        # For simplicity redirect admin to admin dashboard
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('home.html')
    return render_template('home.html')

import uuid

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    # Step 1: Check if admin exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE role = %s", ('admin',))
    admin = cursor.fetchone()
    conn.close()

    if admin:
        flash('Admin account already exists!', 'warning')
        return redirect(url_for('home'))

    # Step 2: Handle form submission
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Simple validation
        if not name or not email or not password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('create_admin'))

        hashed_password = generate_password_hash(password)
        admin_id = str(uuid.uuid4())  # Generate a unique admin ID

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (id, name, email, password, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (admin_id, name, email, hashed_password, 'admin'))
            conn.commit()
            conn.close()

            flash('Admin account created successfully!', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error creating admin: {str(e)}', 'danger')
            return redirect(url_for('create_admin'))

    # Step 3: Render template
    return render_template('create_admin.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if session.get('logged_in'):
        flash('Already logged in.', 'info')
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, password, role FROM users WHERE LOWER(email)=%s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            session['role'] = user[4].lower()
            session['logged_in'] = True
            flash('Logged in successfully', 'success')
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('home'))

# Admin dashboard (shows admin actions)
@app.route('/admin')
@role_required('admin')
def admin_dashboard():
    return render_template('admin.html')

# 1) Import Student Data page
from werkzeug.utils import secure_filename

@app.route('/admin/import', methods=['GET', 'POST'])
def import_students():
    conn = get_db_connection()
    
    if request.method == 'GET':
        # Fetch batches and departments for dropdowns (get names, not IDs)
        cur = conn.cursor()
        cur.execute("SELECT name FROM batches")
        batches = [batch[0] for batch in cur.fetchall()]
        
        cur.execute("SELECT name FROM departments")
        departments = [dept[0] for dept in cur.fetchall()]
        
        cur.close()
        conn.close()
        
        return render_template('import_students.html', 
                             batches=batches, 
                             departments=departments)
    
    # POST request handling
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_manual':
            # Handle manual student entry
            try:
                # Get form data
                name = request.form.get('name')
                father_name = request.form.get('father_name')
                cnic = request.form.get('cnic')
                caste = request.form.get('caste')
                roll_no = request.form.get('roll_no')
                batch = request.form.get('batch')  # This is now the name
                department = request.form.get('department')  # This is now the name
                year = request.form.get('year')
                enrollment = request.form.get('enrollment')
                emergency_contact = request.form.get('emergency_contact')
                relation = request.form.get('relation')
                blood_group = request.form.get('blood_group')
                address = request.form.get('address')
                
                # Validate required fields
                if not all([name, father_name, cnic, caste, roll_no, batch, department, year]):
                    flash('Please fill all required fields', 'danger')
                    return redirect(request.url)
                
                cur = conn.cursor()
                
                # Check if student already exists
                cur.execute("SELECT id FROM students WHERE roll_no = %s", (roll_no,))
                if cur.fetchone():
                    flash(f'Student with roll number {roll_no} already exists!', 'warning')
                    cur.close()
                    conn.close()
                    return redirect(request.url)
                
                # Insert new student with batch and department names
                cur.execute("""
                    INSERT INTO students 
                    (name, father_name, cnic, caste, roll_no, batch, department, year, 
                     enrollment, emergency_contact, relation, blood_group, address)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (name, father_name, cnic, caste, roll_no, batch, department, year,
                      enrollment, emergency_contact, relation, blood_group, address))
                
                conn.commit()
                cur.close()
                conn.close()
                
                flash(f'Student {name} added successfully!', 'success')
                return redirect(request.url)
                
            except Exception as e:
                conn.rollback()
                cur.close()
                conn.close()
                app.logger.exception("Manual student entry error")
                flash('Error adding student: ' + str(e), 'danger')
                return redirect(request.url)
        
        elif action == 'import_file':
            # Handle file import - your existing code but ensure it uses names
            file = request.files.get('file')
            if not file:
                flash('No file provided.', 'warning')
                return redirect(request.url)

            filename = secure_filename(file.filename)
            if not filename.lower().endswith(('.csv', '.xlsx', '.xls')):
                flash('Unsupported file type. Provide CSV or Excel.', 'danger')
                return redirect(request.url)

            try:
                # Read file safely
                if filename.lower().endswith('.csv'):
                    df = pd.read_csv(file)
                else:
                    df = pd.read_excel(file, engine='openpyxl')

                # Normalize column names
                df.columns = [c.strip().lower().replace(' ', '_') for c in df.columns]

                # Must have these columns
                required_cols = {'name', 'father_name', 'cnic', 'caste', 'roll_no', 'batch', 'department'}
                if not required_cols.issubset(df.columns):
                    flash('File must contain columns: name, father_name, cnic, caste, roll_no, batch, department', 'danger')
                    return redirect(request.url)

                # Add any missing optional columns
                optional_cols = [
                    'year', 'enrollment', 'emergency_contact', 'relation', 
                    'blood_group', 'address', 'image_path', 'qr_code'
                ]
                for col in optional_cols:
                    if col not in df.columns:
                        df[col] = ""

                cur = conn.cursor()

                # Fetch all existing batches and departments once (names)
                cur.execute("SELECT name FROM batches")
                existing_batches = {r[0].strip().lower() for r in cur.fetchall()}

                cur.execute("SELECT name FROM departments")
                existing_departments = {r[0].strip().lower() for r in cur.fetchall()}

                # Collect unique batches/departments from CSV
                csv_batches = {str(b).strip().lower() for b in df['batch'].dropna().unique()}
                csv_departments = {str(d).strip().lower() for d in df['department'].dropna().unique()}

                # Validation: ensure all batches & departments exist
                missing_batches = csv_batches - existing_batches
                missing_departments = csv_departments - existing_departments

                if missing_batches or missing_departments:
                    missing_msg = []
                    if missing_batches:
                        missing_msg.append(f"Missing batches: {', '.join(missing_batches)}")
                    if missing_departments:
                        missing_msg.append(f"Missing departments: {', '.join(missing_departments)}")
                    flash("⚠️ Import stopped. " + " | ".join(missing_msg), 'danger')
                    cur.close()
                    conn.close()
                    return redirect(request.url)

                inserted, updated = 0, 0

                # Process valid records
                for _, row in df.iterrows():
                    name = str(row['name']).strip()
                    father_name = str(row['father_name']).strip()
                    cnic = str(row['cnic']).strip()
                    caste = str(row['caste']).strip()
                    roll = str(row['roll_no']).strip()
                    batch_name = str(row['batch']).strip()  # Store name directly
                    dept_name = str(row['department']).strip()  # Store name directly

                    if not name or not roll:
                        continue  # skip incomplete rows

                    # Check if student exists
                    cur.execute("SELECT id FROM students WHERE roll_no = %s", (roll,))
                    existing_student = cur.fetchone()

                    if existing_student:
                        # Update existing student
                        cur.execute("""
                            UPDATE students SET
                                name=%s, father_name=%s, cnic=%s, caste=%s,
                                batch=%s, department=%s, year=%s, enrollment=%s,
                                emergency_contact=%s, relation=%s, blood_group=%s, address=%s
                            WHERE roll_no=%s
                        """, (
                            name, father_name, cnic, caste,
                            batch_name, dept_name,  # Using names directly
                            str(row['year']).strip(),
                            str(row['enrollment']).strip(),
                            str(row['emergency_contact']).strip(),
                            str(row['relation']).strip(),
                            str(row['blood_group']).strip(),
                            str(row['address']).strip(),
                            roll
                        ))
                        updated += 1
                    else:
                        # Insert new student
                        cur.execute("""
                            INSERT INTO students
                            (name, father_name, cnic, caste, roll_no, batch, department, year, enrollment,
                             emergency_contact, relation, blood_group, address)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            name, father_name, cnic, caste, roll, batch_name, dept_name,  # Using names directly
                            str(row['year']).strip(),
                            str(row['enrollment']).strip(),
                            str(row['emergency_contact']).strip(),
                            str(row['relation']).strip(),
                            str(row['blood_group']).strip(),
                            str(row['address']).strip()
                        ))
                        inserted += 1

                conn.commit()
                cur.close()
                conn.close()

                flash(f'Successfully imported {inserted} new students and updated {updated} existing ones.', 'success')
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                app.logger.exception("Import error")
                flash('Error processing file: ' + str(e), 'danger')
                return redirect(request.url)
    
    return redirect(request.url)

@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    conn = get_db_connection()
    
    # Configure upload settings
    UPLOAD_FOLDER = 'static/uploads/students'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB
    
    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    if request.method == 'GET':
        # Fetch batches and departments for dropdowns
        cur = conn.cursor()
        cur.execute("SELECT name FROM batches")
        batches = [batch[0] for batch in cur.fetchall()]
        
        cur.execute("SELECT name FROM departments")
        departments = [dept[0] for dept in cur.fetchall()]
        
        cur.close()
        conn.close()
        
        return render_template('student_register.html', 
                             batches=batches, 
                             departments=departments)
    
    # POST request handling
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name')
            father_name = request.form.get('father_name')
            cnic = request.form.get('cnic')
            caste = request.form.get('caste')
            roll_no = request.form.get('roll_no')
            batch = request.form.get('batch')
            department = request.form.get('department')
            year = request.form.get('year')
            enrollment = request.form.get('enrollment')
            emergency_contact = request.form.get('emergency_contact')
            relation = request.form.get('relation')
            blood_group = request.form.get('blood_group')
            address = request.form.get('address')
            
            # Validate required fields
            if not all([name, father_name, cnic, caste, roll_no, batch, department, year]):
                flash('Please fill all required fields', 'danger')
                return redirect(request.url)
            
            cur = conn.cursor()
            
            # Check if student already exists
            cur.execute("SELECT id FROM students WHERE roll_no = %s", (roll_no,))
            if cur.fetchone():
                flash(f'Student with roll number {roll_no} already exists!', 'warning')
                cur.close()
                conn.close()
                return redirect(request.url)
            
            # Handle image upload
            image_path = None
            if 'student_image' in request.files:
                file = request.files['student_image']
                if file and file.filename != '' and file.filename != 'undefined':
                    if file.content_length > MAX_FILE_SIZE:
                        flash('File size too large. Maximum 2MB allowed.', 'danger')
                        cur.close()
                        conn.close()
                        return redirect(request.url)
                    
                    if allowed_file(file.filename):
                        # Create upload directory if it doesn't exist
                        if not os.path.exists(UPLOAD_FOLDER):
                            os.makedirs(UPLOAD_FOLDER)
                        
                        # Generate secure filename
                        file_ext = file.filename.rsplit('.', 1)[1].lower()
                        filename = f"{roll_no}_{name.replace(' ', '_')}_{int(time.time())}.{file_ext}"
                        filename = secure_filename(filename)
                        
                        # Save file
                        file_path = os.path.join(UPLOAD_FOLDER, filename)
                        file.save(file_path)
                        
                        # Store relative path for web display
                        image_path = f"uploads/students/{filename}"
                    else:
                        flash('Invalid file type. Only PNG, JPG, JPEG, GIF allowed.', 'danger')
                        cur.close()
                        conn.close()
                        return redirect(request.url)
            
            # Insert new student
            cur.execute("""
                INSERT INTO students 
                (name, father_name, cnic, caste, roll_no, batch, department, year, 
                 enrollment, emergency_contact, relation, blood_group, address, image_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (name, father_name, cnic, caste, roll_no, batch, department, year,
                  enrollment, emergency_contact, relation, blood_group, address, image_path))
            
            conn.commit()
            cur.close()
            conn.close()
            
            if image_path:
                flash(f'Registration successful! Student {name} has been registered with image.', 'success')
            else:
                flash(f'Registration successful! Student {name} has been registered.', 'success')
            
            return redirect(url_for('student_register'))
                
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            app.logger.exception("Student registration error")
            flash(f'Error during registration: {str(e)}', 'danger')
            return redirect(request.url)
    
    return redirect(url_for('student_register'))

@app.route('/admin/upload_image/<int:student_id>', methods=['POST'])
@role_required('admin')
def upload_image(student_id):
    file = request.files.get('image')
    if not file:
        return jsonify({'status': 'error', 'message': 'No file provided'}), 400
    if not allowed_image(file.filename):
        return jsonify({'status': 'error', 'message': 'Unsupported image type'}), 400

    filename = secure_filename(f"{student_id}_{file.filename}")
    upload_folder = os.path.join('static', 'uploads', 'student_images')
    os.makedirs(upload_folder, exist_ok=True)

    dest = os.path.join(upload_folder, filename)
    file.save(dest)

    # ✅ Store relative path (WITHOUT static/)
    rel_path = os.path.join('uploads', 'student_images', filename)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE students SET image_path=%s WHERE id=%s", (rel_path, student_id))
    conn.commit()
    cur.close()
    conn.close()

    # ✅ Return correct static URL for live preview
    return jsonify({
        'status': 'ok',
        'image_path': url_for('static', filename=rel_path)
    }), 200 

# 2) Generate Student ID - filter and list students
@app.route('/admin/generate', methods=['GET', 'POST'])
@role_required('admin')
def generate_id():
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch batches and departments
    cur.execute("SELECT name FROM batches ORDER BY name")
    batches = [r[0] for r in cur.fetchall()]

    cur.execute("SELECT name FROM departments ORDER BY name")
    departments = [r[0] for r in cur.fetchall()]

    students = []

    if request.method == 'POST':
        batch = request.form.get('batch', '')
        department = request.form.get('department', '')

        query = """
            SELECT s.id, s.name, s.father_name, s.roll_no, s.department, s.batch, s.year, s.image_path, s.qr_code, d.degree
            FROM students s
            LEFT JOIN departments d ON LOWER(s.department) = LOWER(d.name)
            WHERE (%s = '' OR s.batch = %s)
              AND (%s = '' OR s.department = %s)
            ORDER BY s.name
        """
        cur.execute(query, (batch, batch, department, department))
        students = cur.fetchall()

        qr_folder = os.path.join(current_app.root_path, 'static', 'qr_codes')
        os.makedirs(qr_folder, exist_ok=True)

        for student in students:
            student_id, name, father_name, roll_no, dept_name, batch, year, image_path, qr_code, degree = student

            qr_text = f"""STUDENT ID CARD
Benazir Bhutto Shaheed University

Name: {name}
Roll No: {roll_no}
Department: {dept_name}
Degree: {degree or 'N/A'}
Batch: {batch}
Year: {year}
Father Name: {father_name}

If found, please return to university."""

            qr = qrcode.QRCode(
                version=3,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=8,
                border=2
            )
            qr.add_data(qr_text)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")

            qr_filename = f"qr_{student_id}.png"
            qr_path = os.path.join(qr_folder, qr_filename)
            img.save(qr_path)

            qr_relative_path = f"qr_codes/{qr_filename}"
            cur.execute(
                "UPDATE students SET qr_code = %s WHERE id = %s",
                (qr_relative_path, student_id)
            )
            conn.commit()

    cur.close()
    conn.close()

    return render_template(
        'generate_id.html',
        batches=batches,
        departments=departments,
        students=students
    )


# Serve a printable HTML for a student's ID (used by JS to render modal & download)
@app.route('/admin/id_preview/<int:student_id>')
@role_required('admin')
def id_preview(student_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT s.id, s.name, s.father_name, s.caste, s.cnic, s.roll_no,
               s.department, s.batch, s.year, s.enrollment,
               s.emergency_contact, s.relation, s.blood_group, s.address,
               s.image_path, s.qr_code, d.degree
        FROM students s
        LEFT JOIN departments d ON LOWER(s.department) = LOWER(d.name)
        WHERE s.id = %s
    """, (student_id,))
    s = cur.fetchone()
    cur.close()
    conn.close()

    if not s:
        abort(404)

    student = {
        'id': s[0],
        'name': s[1],
        'father_name': s[2],
        'caste': s[3],
        'cnic': s[4],
        'roll_no': s[5],
        'department': s[6],
        'batch': s[7],
        'year': s[8],
        'enrollment': s[9],
        'emergency_contact': s[10],
        'relation': s[11],
        'blood_group': s[12],
        'address': s[13],
        'image_path': s[14],
        'qr_code': s[15],
        'degree': s[16] or "Bachelor of Engineering Technology"
    }

    if student['qr_code']:
        student['qr_code_url'] = url_for('static', filename=student['qr_code'])
    else:
        student['qr_code_url'] = None

    return render_template('id_modal.html', student=student)

@app.route('/admin/id_card/<int:student_id>')
@role_required('admin')
def generate_id_modal(student_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT s.id, s.name, s.father_name, s.roll_no, s.batch, s.department,
               s.year, s.enrollment, s.emergency_contact, s.relation,
               s.blood_group, s.address, s.image_path, s.qr_code, d.degree
        FROM students s
        LEFT JOIN departments d ON LOWER(s.department) = LOWER(d.name)
        WHERE s.id = %s
    """, (student_id,))
    s = cur.fetchone()
    cur.close()
    conn.close()

    if not s:
        flash("Student not found", "danger")
        return redirect(url_for('admin_dashboard'))

    keys = [
        'id', 'name', 'father_name', 'roll_no', 'batch', 'department', 'year', 'enrollment',
        'emergency_contact', 'relation', 'blood_group', 'address', 'image_path', 'qr_code', 'degree'
    ]
    student_dict = dict(zip(keys, s))

    if student_dict['image_path'] and student_dict['image_path'].startswith('static/'):
        student_dict['image_path'] = student_dict['image_path'].replace('static/', '')

    # Fallback if department has no degree assigned yet
    if not student_dict.get('degree'):
        student_dict['degree'] = "Bachelor of Engineering Technology"

    return render_template('id_modal.html', student=student_dict)


    # Manage Batches
@app.route('/admin/manage_batches', methods=['GET', 'POST'])
@role_required("admin")
def manage_batches():
    if request.method == 'POST':
        if 'add_batch' in request.form:
            batch_name = request.form['batch_name']
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO batches (name) VALUES (%s)', (batch_name,))
            conn.commit()
            conn.close()
            flash('Batch added successfully!', 'success')
        elif 'delete_batch' in request.form:
            batch_id = request.form['batch_id']
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM batches WHERE id = %s', (batch_id,))
            conn.commit()
            conn.close()
            flash('Batch deleted successfully!', 'success')
        return redirect(url_for('manage_batches'))

    # Fetch all batches
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM batches')
    batches = cursor.fetchall()
    conn.close()
    return render_template('batches.html', batches=batches)

# Manage Departments
@app.route('/admin/manage_departments', methods=['GET', 'POST'])
@role_required("admin")
def manage_departments():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Add Department
        if 'add_department' in request.form:
            department_name = request.form.get('department_name', '').strip()
            degree = request.form.get('degree', '').strip()

            if not department_name or not degree:
                flash('Department name and degree are required.', 'warning')
                return redirect(url_for('manage_departments'))

            try:
                cursor.execute(
                    'INSERT INTO departments (name, degree) VALUES (%s, %s)',
                    (department_name, degree)
                )
                conn.commit()
                flash('Department added successfully!', 'success')
            except Exception as e:
                conn.rollback()
                if 'unique constraint' in str(e).lower():
                    flash('Department already exists.', 'warning')
                else:
                    flash(f'Error adding department: {e}', 'danger')

        # Delete Department
        elif 'delete_department' in request.form:
            department_id = request.form.get('department_id')
            try:
                cursor.execute('DELETE FROM departments WHERE id = %s', (department_id,))
                conn.commit()
                flash('Department deleted successfully!', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Error deleting department: {e}', 'danger')

        conn.close()
        return redirect(url_for('manage_departments'))

    # Fetch all departments
    cursor.execute('SELECT * FROM departments ORDER BY id ASC')
    departments = cursor.fetchall()

    conn.close()
    return render_template('departments.html', departments=departments)

@app.route('/admin/edit_student/<int:student_id>', methods=['GET', 'POST'])
@role_required("admin")
def edit_student(student_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Handle Update
        name = request.form.get('name', '').strip()
        father_name = request.form.get('father_name', '').strip()
        cnic = request.form.get('cnic', '').strip()
        caste = request.form.get('caste', '').strip()
        roll_no = request.form.get('roll_no', '').strip()
        batch = request.form.get('batch', '').strip()
        department = request.form.get('department', '').strip()
        year = request.form.get('year', '').strip()
        enrollment = request.form.get('enrollment', '').strip()
        emergency_contact = request.form.get('emergency_contact', '').strip()
        relation = request.form.get('relation', '').strip()
        blood_group = request.form.get('blood_group', '').strip()
        address = request.form.get('address', '').strip()

        # Validate required fields
        if not all([name, father_name, cnic, caste, roll_no, batch, department, year]):
            flash('Please fill all required fields.', 'warning')
            cursor.close()
            conn.close()
            return redirect(request.url)

        # Handle image upload
        image_path = None
        if 'student_image' in request.files:
            file = request.files['student_image']
            if file and file.filename:
                UPLOAD_FOLDER = 'static/uploads/students'
                ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
                MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

                if file.content_length and file.content_length > MAX_FILE_SIZE:
                    flash('File size too large (max 2MB).', 'warning')
                    cursor.close()
                    conn.close()
                    return redirect(request.url)

                if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
                    if not os.path.exists(UPLOAD_FOLDER):
                        os.makedirs(UPLOAD_FOLDER)

                    ext = file.filename.rsplit('.', 1)[1].lower()
                    filename = f"{roll_no}_{name.replace(' ', '_')}_{int(time.time())}.{ext}"
                    filename = secure_filename(filename)
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)
                    image_path = f"uploads/students/{filename}"

                    # Delete old image
                    cursor.execute("SELECT image_path FROM students WHERE id = %s", (student_id,))
                    old_img = cursor.fetchone()
                    if old_img and old_img[0]:
                        old_path = os.path.join('static', old_img[0])
                        if os.path.exists(old_path):
                            os.remove(old_path)
                else:
                    flash('Invalid file type. Only PNG, JPG, JPEG, GIF allowed.', 'warning')
                    cursor.close()
                    conn.close()
                    return redirect(request.url)

        # Update student record
        cursor.execute("""
            UPDATE students SET
                name = %s,
                father_name = %s,
                cnic = %s,
                caste = %s,
                roll_no = %s,
                batch = %s,
                department = %s,
                year = %s,
                enrollment = %s,
                emergency_contact = %s,
                relation = %s,
                blood_group = %s,
                address = %s,
                image_path = COALESCE(%s, image_path)
            WHERE id = %s
        """, (name, father_name, cnic, caste, roll_no, batch, department, year,
              enrollment, emergency_contact, relation, blood_group, address, image_path, student_id))

        conn.commit()
        cursor.close()
        conn.close()
        flash(f'Student {name} updated successfully!', 'success')
        return redirect(url_for('generate_id'))

    # GET request: render edit form
    cursor.execute("SELECT * FROM students WHERE id = %s", (student_id,))
    student_row = cursor.fetchone()
    if not student_row:
        flash('Student record not found.', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('generate_id'))

    # Convert tuple to dict for template
    columns = [desc[0] for desc in cursor.description]
    student = dict(zip(columns, student_row))

    # Fetch dropdowns
    cursor.execute("SELECT name FROM batches")
    batches = [b[0] for b in cursor.fetchall()]

    cursor.execute("SELECT name FROM departments")
    departments = [d[0] for d in cursor.fetchall()]

    cursor.close()
    conn.close()
    return render_template('edit_student.html', student=student, batches=batches, departments=departments)


@app.route('/admin/delete_student/<int:student_id>', methods=['POST'])
@role_required("admin")
def delete_student(student_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch student image
    cursor.execute("SELECT image_path FROM students WHERE id = %s", (student_id,))
    student = cursor.fetchone()

    # Delete student record
    cursor.execute("DELETE FROM students WHERE id = %s", (student_id,))
    conn.commit()

    # Remove image if exists
    if student and student[0]:
        img_path = os.path.join('static', student[0])
        if os.path.exists(img_path):
            os.remove(img_path)

    cursor.close()
    conn.close()
    flash("Student record deleted successfully.", 'success')
    return redirect(url_for('students_dashboard'))

@app.route('/ai/message', methods=['POST'])
def ai_message():
    data = request.get_json(silent=True)
    if not data or 'message' not in data:
        return jsonify({"message": "No message provided"}), 400

    user_msg = data['message']
    print(f"📨 User message: '{user_msg}'")

    # 🎯 NEW: Handle logout commands immediately (HIGHEST PRIORITY)
    user_msg_lower = user_msg.lower().strip()
    
    logout_keywords = [
        'logout', 'log out', 'signout', 'sign out',
        'log off', 'sign off', 'shut', 'shut off', 'switch off', 'unplug', 'end session', 'home', 'home page'
    ]
    
    if any(keyword in user_msg_lower for keyword in logout_keywords):
        print("🎯 Detected LOGOUT command")
        return jsonify({
            "message": "👋 Goodbye Admin, logging out!",
            "redirect_url": "/logout",
            "action": "logout",
            "delay": 7000  # 7 seconds delay
        })

    # 🎯 NEW: Handle close AI assistant commands
    close_ai_keywords = [
        'close', 'quit', 'exit', 'leave', 'stop', 'finish', 'close ai', 
        'goodbye kazmi', 'bye kazmi', 'see you kazmi', 'see you', 'bye', 'goodbye', 'discontinue',
        'close chat', 'exit chat', 'end chat', 'stop chat'
    ]
    
    if any(keyword in user_msg_lower for keyword in close_ai_keywords):
        print("🎯 Detected CLOSE AI command")
        return jsonify({
            "message": "👋 See you next time!",
            "action": "close_chat",
            "delay": 3500  # 3.5 seconds delay
        })

    # 🎯 Handle back/return commands
    if user_msg_lower in ['back', 'return', 'go back', 'main page', 'admin page']:
        print("🎯 Detected BACK/RETURN command")
        return jsonify({
            "message": "🔙 Returning to main admin page...",
            "redirect_url": "/admin",
            "action": "redirect"
        })

    # Smart routing based on message content
    # 🎯 FIXED: More specific page navigation patterns
    page_nav_patterns = [
        'enter page', 'open page', 'go to page', 'navigate to page', 'access page',
        'enter a', 'open a', 'go to a', 'enter b', 'open b', 'go to b',
        'enter c', 'open c', 'go to c', 'enter d', 'open d', 'go to d',
        'import page', 'generate ids page', 'manage batches page', 'manage departments page'
    ]
    
    # Department-related keywords
    department_keywords = [
        'department', 'dept', 
        'computer science', 'electrical', 'mechanical', 'civil', 
        'software', 'artificial intelligence', 'bba', 'mba',
        'bachelor of science', 'bachelor of engineering',
        'show department', 'list department', 'view department', 'departments',
        'delete department', 'remove department', 'del department', 
        'add department', 'create department', 'new department',
        '1', '2', 'bs', 'bet'
    ]
    
    # Batch-related keywords  
    batch_keywords = [
        'batch', 'bscs', 'mscs', 'bsit', 'bsse',
        'show batch', 'list batch', 'view batch',
        'delete batch', 'remove batch', 'del batch',
        'add batch', 'create batch', 'new batch'
    ]
    
    # Determine which workflow to call with priority logic
    workflow_type = "batch"  # Default to batch
    
    # 🎯 FIXED: Check for EXACT page navigation patterns first
    has_exact_page_nav = any(pattern in user_msg_lower for pattern in page_nav_patterns)
    
    if has_exact_page_nav:
        workflow_type = "page_navigation"
        print("🎯 Detected as PAGE NAVIGATION command")
    
    # 🎯 FIXED: Check for department operations with specific commands
    elif any(keyword in user_msg_lower for keyword in department_keywords):
        # Make sure it's a department OPERATION, not navigation
        is_department_operation = any(cmd in user_msg_lower for cmd in [
            'show department', 'list department', 'view department', 'departments',
            'add department', 'create department', 'new department',
            'delete department', 'remove department', 'del department',
            '1', '2', 'bs', 'bet'
        ])
        
        if is_department_operation:
            workflow_type = "department"
            print("🎯 Detected as DEPARTMENT operation")
    
    # 🎯 FIXED: Check for batch operations with specific commands
    elif any(keyword in user_msg_lower for keyword in batch_keywords):
        # Make sure it's a batch OPERATION, not navigation
        is_batch_operation = any(cmd in user_msg_lower for cmd in [
            'show batch', 'list batch', 'view batch', 'batches',
            'add batch', 'create batch', 'new batch',
            'delete batch', 'remove batch', 'del batch'
        ])
        
        if is_batch_operation:
            workflow_type = "batch"
            print("🎯 Detected as BATCH operation")
    
    # Set the n8n URL based on workflow type
    if workflow_type == "department":
        n8n_url = "http://localhost:5678/webhook/ai-department-agent"
    elif workflow_type == "page_navigation":
        n8n_url = "http://localhost:5678/webhook/ai-page-navigation-agent"
    else:
        n8n_url = "http://localhost:5678/webhook/ai-batch-agent"
    
    print(f"🔄 Routing to {workflow_type.upper()} workflow: {n8n_url}")

    try:
        response = requests.post(
            n8n_url,
            json={"message": user_msg},
            timeout=15
        )
        
        print(f"📡 Response status: {response.status_code}")
        
        # Handle HTTP errors
        if response.status_code != 200:
            print(f"❌ HTTP Error: {response.text}")
            error_msg = "Workflow returned an error. Please try again."
            if workflow_type == "page_navigation":
                return jsonify({"message": error_msg, "action": "message"})
            else:
                return jsonify({"message": error_msg}), 500
        
        # Parse JSON response
        result = response.json()
        print(f"📊 Raw n8n response: {result}")
        
        # SPECIAL HANDLING FOR PAGE NAVIGATION WORKFLOW
        if workflow_type == "page_navigation":
            return handle_page_navigation_response(result, user_msg)
        else:
            return handle_operation_response(result)

    except requests.exceptions.ConnectionError:
        print("❌ Connection error to n8n")
        error_msg = "Cannot connect to workflow engine. Please try again later."
        if workflow_type == "page_navigation":
            return jsonify({"message": error_msg, "action": "message"})
        else:
            return jsonify({"message": error_msg}), 500
    except requests.exceptions.Timeout:
        print("⏰ Request timeout")
        error_msg = "Request timeout. Please try again."
        if workflow_type == "page_navigation":
            return jsonify({"message": error_msg, "action": "message"})
        else:
            return jsonify({"message": error_msg}), 500
    except requests.exceptions.RequestException as e:
        print(f"🔧 Request exception: {e}")
        error_msg = f"Workflow error: {str(e)}"
        if workflow_type == "page_navigation":
            return jsonify({"message": error_msg, "action": "message"})
        else:
            return jsonify({"message": error_msg}), 500
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        error_msg = "An unexpected error occurred. Please try again."
        if workflow_type == "page_navigation":
            return jsonify({"message": error_msg, "action": "message"})
        else:
            return jsonify({"message": error_msg}), 500


def handle_page_navigation_response(result, original_message):
    """Handle responses specifically from page navigation workflow"""
    try:
        friendly_message = "Ready to navigate..."
        redirect_url = ""
        action = "message"
        
        # Extract data from n8n response
        if isinstance(result, list) and len(result) > 0:
            first_item = result[0]
            if isinstance(first_item, dict) and "json" in first_item:
                json_data = first_item["json"]
                friendly_message = json_data.get("message", "Navigation ready")
                redirect_url = json_data.get("redirect_url", "")
                action = json_data.get("action", "message")
        
        elif isinstance(result, dict):
            friendly_message = result.get("message", "Navigation ready")
            redirect_url = result.get("redirect_url", "")
            action = result.get("action", "message")
        
        # Clean the message
        friendly_message = str(friendly_message).strip()
        friendly_message = friendly_message.replace('\\n', '\n')
        friendly_message = friendly_message.replace('\\"', '"')
        
        # Remove surrounding quotes if present
        if (friendly_message.startswith("'") and friendly_message.endswith("'")) or \
           (friendly_message.startswith('"') and friendly_message.endswith('"')):
            friendly_message = friendly_message[1:-1]
        
        print(f"🎯 Page navigation - Message: {friendly_message}")
        print(f"🎯 Page navigation - Redirect URL: {redirect_url}")
        print(f"🎯 Page navigation - Action: {action}")
        
        # Return structured response for page navigation
        return jsonify({
            "message": friendly_message,
            "redirect_url": redirect_url,
            "action": action
        })
        
    except Exception as e:
        print(f"💥 Error handling page navigation response: {e}")
        return jsonify({
            "message": "❌ Navigation error. Please try again.",
            "action": "message"
        })


def handle_operation_response(result):
    """Handle responses from department/batch operation workflows"""
    try:
        friendly_message = "Action completed successfully"
        
        # Extract message from n8n response
        if isinstance(result, list) and len(result) > 0:
            first_item = result[0]
            print(f"📋 First item: {first_item}")
            
            if isinstance(first_item, dict) and "json" in first_item:
                json_data = first_item["json"]
                print(f"📋 JSON data: {json_data}")
                
                friendly_message = json_data.get("message") or json_data.get("MESSAGE") or "Action completed"
            else:
                friendly_message = str(first_item)
                
        elif isinstance(result, dict):
            print(f"📋 Dict response: {result}")
            friendly_message = result.get("message") or result.get("MESSAGE") or "Action completed"
        else:
            friendly_message = str(result)

        # Clean and format the message
        friendly_message = str(friendly_message).strip()
        friendly_message = friendly_message.replace('\\n', '\n')
        friendly_message = friendly_message.replace('\\"', '"')
        
        # Remove surrounding quotes if present
        if (friendly_message.startswith("'") and friendly_message.endswith("'")) or \
           (friendly_message.startswith('"') and friendly_message.endswith('"')):
            friendly_message = friendly_message[1:-1]
        
        # Remove any remaining JSON artifacts
        friendly_message = friendly_message.replace('{', '').replace('}', '')
        
        print(f"📤 Final operation message: {friendly_message}")
        return jsonify({"message": friendly_message})
        
    except Exception as e:
        print(f"💥 Error handling operation response: {e}")
        return jsonify({"message": "Action completed with issues"})
    
@app.route('/ai/chat')
@role_required('admin')
def ai_chat_page():
    return render_template('ai_chat.html')


if __name__ == '__main__':
    #init_db()
    #app.run(debug=True)
    app.run(host="0.0.0.0", port=5000, debug=True)